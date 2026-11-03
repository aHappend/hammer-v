module hammer_v5_l2 #(
    parameter integer L2_SETS = 64,
    parameter integer PREFETCH_ENABLE = 1
) (
    input wire clk, rst_n,
    input wire req_valid,
    input wire [1:0] req_cmd,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire req_ready, rsp_valid, rsp_error,
    output wire [63:0] rsp_rdata,
    input wire rsp_ready,
    output wire mem_valid, mem_write,
    input wire mem_ready,
    output wire [63:0] mem_addr, mem_wdata,
    output wire [7:0] mem_wstrb,
    input wire mem_rsp_valid, mem_error,
    input wire [63:0] mem_rdata,
    output wire mem_rsp_ready,
    input wire prefetch_block,
    output wire event_l2_access, event_l2_hit
);
    localparam integer LEGAL = (L2_SETS == 1 || L2_SETS == 4 ||
        L2_SETS == 16 || L2_SETS == 64) &&
        (PREFETCH_ENABLE == 0 || PREFETCH_ENABLE == 1);
    initial if (!LEGAL)
        $fatal(1, "PARAMETER ERROR: illegal HAMMER-V5 L2 configuration");
    generate if (LEGAL) begin : g_legal
        localparam integer IW = L2_SETS == 1 ? 1 : $clog2(L2_SETS);
        localparam integer AW = $clog2(L2_SETS*4);
        localparam [3:0] IDLE=0, CAPTURE=1, SELECT=2, HIT_FINISH=3,
            RESPONSE=4, FILL_ISSUE=5, FILL_WAIT=6, FILL_STORE=7,
            FILL_FINISH=8, WRITE_ISSUE=9, WRITE_WAIT=10, MAINTENANCE=11;
        localparam [63:0] DRAM_BASE=64'h80000000, DRAM_LIMIT=64'h100000000;
        reg [3:0] state;
        reg [63:0] addr_q, write_q, read_q, selected_q;
        reg [63:0] fill_q, fill_read_q, prefetch_addr_q;
        reg [7:0] mask_q;
        reg [1:0] cmd_q, way_q, beat_q;
        reg [IW-1:0] set_q, scan_q;
        reg error_q, prefetch_q, prefetch_pending;
        reg access_q, hit_q;
        reg [L2_SETS-1:0] valid_way [0:3];
        reg [1:0] replacement [0:L2_SETS-1];
        wire [63:0] ram_data [0:3];
        wire [58:0] ram_tag [0:3];
        reg [63:0] data_snapshot [0:3];
        reg [58:0] tag_snapshot [0:3];
        reg [3:0] valid_read_q, valid_snapshot;
        wire accept = req_valid && req_ready;
        wire bad_request = |req_addr[2:0] ||
            req_addr < DRAM_BASE || req_addr >= DRAM_LIMIT;
        wire start_demand = accept && !req_cmd[1] && !bad_request;
        wire start_prefetch = rst_n && state == IDLE && !req_valid &&
            prefetch_pending && !prefetch_block;
        wire read_enable = start_demand || start_prefetch;
        wire [63:0] lookup_addr = start_prefetch ? prefetch_addr_q : req_addr;
        wire [IW-1:0] lookup_set = L2_SETS == 1 ? {IW{1'b0}} :
            lookup_addr[IW+4:5];
        wire [AW-1:0] lookup_word = lookup_addr[AW+2:3];
        wire [63:0] wanted_base = {addr_q[63:5],5'b0};
        wire [63:0] next_line = wanted_base + 64'd32;
        wire [63:0] fill_addr = wanted_base + {59'b0,beat_q,3'b0};
        wire abandon_prefetch = prefetch_q && (req_valid || prefetch_block);
        wire [3:0] hits = {
            valid_snapshot[3] && tag_snapshot[3] == addr_q[63:5],
            valid_snapshot[2] && tag_snapshot[2] == addr_q[63:5],
            valid_snapshot[1] && tag_snapshot[1] == addr_q[63:5],
            valid_snapshot[0] && tag_snapshot[0] == addr_q[63:5]};
        wire [1:0] matching_way = hits[0] ? 2'd0 : hits[1] ? 2'd1 :
            hits[2] ? 2'd2 : 2'd3;
        wire [1:0] victim_way = !valid_snapshot[0] ? 2'd0 :
            !valid_snapshot[1] ? 2'd1 : !valid_snapshot[2] ? 2'd2 :
            !valid_snapshot[3] ? 2'd3 : replacement[set_q];
        wire fill_store = rst_n && state == FILL_STORE && !abandon_prefetch;
        wire write_store = rst_n && state == WRITE_WAIT &&
            mem_rsp_valid && !mem_error;
        wire [AW-1:0] fill_word = {set_q,beat_q};
        wire [AW-1:0] write_word = addr_q[AW+2:3];
        wire [AW-1:0] ram_write_word = fill_store ? fill_word : write_word;
        wire [63:0] ram_write_data = fill_store ? fill_q : write_q;
        wire [7:0] ram_write_mask = fill_store ? 8'hff : mask_q;
        integer way, entry;
        genvar w, lane;

        assign req_ready = rst_n && state == IDLE;
        assign rsp_valid = rst_n && state == RESPONSE;
        assign rsp_error = rsp_valid && error_q;
        assign rsp_rdata = rsp_valid && !error_q ? read_q : 64'b0;
        assign event_l2_access = rst_n && access_q;
        assign event_l2_hit = rst_n && hit_q;
        assign mem_valid = rst_n &&
            ((state == FILL_ISSUE && !abandon_prefetch && (!prefetch_q || mem_ready)) ||
             state == WRITE_ISSUE);
        assign mem_write = mem_valid && state == WRITE_ISSUE;
        assign mem_addr = !mem_valid ? 64'b0 : mem_write ? addr_q : fill_addr;
        assign mem_wdata = mem_write ? write_q : 64'b0;
        assign mem_wstrb = mem_write ? mask_q : 8'b0;
        assign mem_rsp_ready = rst_n && (state == FILL_WAIT || state == WRITE_WAIT);

        for (w = 0; w < 4; w = w + 1) begin : g_way
            (* ramstyle = "M20K", nomem2reg *)
            reg [58:0] tags [0:L2_SETS-1];
            reg [58:0] tag_read_q;
            always @(posedge clk) begin
                if (read_enable) tag_read_q <= tags[lookup_set];
                if (fill_store && beat_q == 3 && way_q == w)
                    tags[set_q] <= addr_q[63:5];
            end
            assign ram_tag[w] = tag_read_q;
            for (lane = 0; lane < 8; lane = lane + 1) begin : g_byte
                (* ramstyle = "M20K", nomem2reg *)
                reg [7:0] bytes [0:L2_SETS*4-1];
                reg [7:0] byte_read_q;
                always @(posedge clk) begin
                    if (read_enable) byte_read_q <= bytes[lookup_word];
                    if ((fill_store || write_store) && way_q == w &&
                        ram_write_mask[lane])
                        bytes[ram_write_word] <= ram_write_data[lane*8 +: 8];
                end
                assign ram_data[w][lane*8 +: 8] = byte_read_q;
            end
        end
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                state <= IDLE;
                addr_q <= 0;
                write_q <= 0;
                read_q <= 0;
                selected_q <= 0;
                fill_q <= 0;
                fill_read_q <= 0;
                prefetch_addr_q <= 0;
                mask_q <= 0;
                cmd_q <= 0;
                way_q <= 0;
                beat_q <= 0;
                set_q <= 0;
                scan_q <= 0;
                error_q <= 0;
                prefetch_q <= 0;
                prefetch_pending <= 0;
                valid_read_q <= 0;
                valid_snapshot <= 0;
                access_q <= 0;
                hit_q <= 0;
                for (way = 0; way < 4; way = way + 1) begin
                    valid_way[way] <= {L2_SETS{1'b0}};
                    data_snapshot[way] <= 0;
                    tag_snapshot[way] <= 0;
                end
                for (entry = 0; entry < L2_SETS; entry = entry + 1)
                    replacement[entry] <= 0;
            end else begin
                access_q <= 0;
                hit_q <= 0;
                if (read_enable)
                    for (way = 0; way < 4; way = way + 1)
                        valid_read_q[way] <= valid_way[way][lookup_set];
                if (prefetch_block) prefetch_pending <= 0;
                case (state)
                    IDLE: begin
                        if (accept) begin
                            addr_q <= req_addr;
                            write_q <= req_cmd == 1 ? req_wdata : 64'b0;
                            mask_q <= req_cmd == 1 ? req_wstrb : 8'b0;
                            cmd_q <= req_cmd;
                            set_q <= lookup_set;
                            read_q <= 0;
                            error_q <= 0;
                            prefetch_q <= 0;
                            if (req_cmd[1]) begin
                                prefetch_pending <= 0;
                                scan_q <= 0;
                                state <= MAINTENANCE;
                            end else if (bad_request) begin
                                error_q <= 1;
                                state <= RESPONSE;
                            end else begin
                                access_q <= 1;
                                state <= CAPTURE;
                            end
                        end else if (start_prefetch) begin
                            addr_q <= prefetch_addr_q;
                            write_q <= 0;
                            mask_q <= 0;
                            cmd_q <= 0;
                            set_q <= lookup_set;
                            prefetch_q <= 1;
                            prefetch_pending <= 0;
                            state <= CAPTURE;
                        end
                    end
                    CAPTURE: begin
                        if (abandon_prefetch) state <= IDLE;
                        else begin
                            for (way = 0; way < 4; way = way + 1) begin
                                data_snapshot[way] <= ram_data[way];
                                tag_snapshot[way] <= ram_tag[way];
                            end
                            valid_snapshot <= valid_read_q;
                            state <= SELECT;
                        end
                    end
                    SELECT: begin
                        if (abandon_prefetch) state <= IDLE;
                        else if (|hits) begin
                            way_q <= matching_way;
                            if (prefetch_q) state <= IDLE;
                            else begin
                                hit_q <= 1;
                                if (cmd_q == 0) begin
                                    selected_q <= data_snapshot[matching_way];
                                    state <= HIT_FINISH;
                                end else state <= WRITE_ISSUE;
                            end
                        end else begin
                            way_q <= victim_way;
                            valid_way[victim_way][set_q] <= 0;
                            beat_q <= 0;
                            fill_read_q <= 0;
                            state <= FILL_ISSUE;
                        end
                    end
                    HIT_FINISH: begin
                        read_q <= selected_q;
                        state <= RESPONSE;
                    end
                    FILL_ISSUE: begin
                        if (abandon_prefetch) state <= IDLE;
                        else if (mem_ready) state <= FILL_WAIT;
                    end
                    FILL_WAIT: if (mem_rsp_valid) begin
                        if (mem_error || abandon_prefetch) begin
                            if (prefetch_q) state <= IDLE;
                            else begin
                                error_q <= 1;
                                state <= RESPONSE;
                            end
                        end else begin
                            fill_q <= mem_rdata;
                            if (beat_q == addr_q[4:3]) fill_read_q <= mem_rdata;
                            state <= FILL_STORE;
                        end
                    end
                    FILL_STORE: begin
                        if (abandon_prefetch) state <= IDLE;
                        else if (beat_q == 3) begin
                            valid_way[way_q][set_q] <= 1;
                            replacement[set_q] <= way_q + 2'd1;
                            state <= FILL_FINISH;
                        end else begin
                            beat_q <= beat_q + 2'd1;
                            state <= FILL_ISSUE;
                        end
                    end
                    FILL_FINISH: begin
                        if (prefetch_q) state <= IDLE;
                        else if (cmd_q == 1) state <= WRITE_ISSUE;
                        else begin
                            read_q <= fill_read_q;
                            state <= RESPONSE;
                            if (PREFETCH_ENABLE == 1 && !prefetch_block &&
                                next_line >= DRAM_BASE && next_line < DRAM_LIMIT) begin
                                prefetch_addr_q <= next_line;
                                prefetch_pending <= 1;
                            end
                        end
                    end
                    WRITE_ISSUE: if (mem_ready) state <= WRITE_WAIT;
                    WRITE_WAIT: if (mem_rsp_valid) begin
                        if (mem_error) begin
                            valid_way[way_q][set_q] <= 0;
                            error_q <= 1;
                        end
                        state <= RESPONSE;
                    end
                    MAINTENANCE: begin
                        if (cmd_q == 3)
                            for (way = 0; way < 4; way = way + 1)
                                valid_way[way][scan_q] <= 0;
                        if (cmd_q == 2 || scan_q == L2_SETS-1)
                            state <= RESPONSE;
                        else scan_q <= scan_q + {{(IW-1){1'b0}},1'b1};
                    end
                    RESPONSE: if (rsp_ready) state <= IDLE;
                    default: state <= IDLE;
                endcase
            end
        end
    end else begin : g_illegal
        assign req_ready = 1'b0;
        assign rsp_valid = 1'b0;
        assign rsp_error = 1'b0;
        assign rsp_rdata = 64'b0;
        assign mem_valid = 1'b0;
        assign mem_write = 1'b0;
        assign mem_addr = 64'b0;
        assign mem_wdata = 64'b0;
        assign mem_wstrb = 8'b0;
        assign mem_rsp_ready = 1'b0;
        assign event_l2_access = 1'b0;
        assign event_l2_hit = 1'b0;
    end endgenerate
endmodule
