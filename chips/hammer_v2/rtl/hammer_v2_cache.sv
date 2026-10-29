module hammer_v2_cache #(
    parameter integer LINES = 64,
    parameter integer WORDS = 8192,
    parameter integer READ_ONLY = 0
) (
    input wire clk, rst_n, req_valid,
    input wire [1:0] req_cmd,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire req_ready,
    output wire rsp_valid,
    output wire [63:0] rsp_rdata,
    output wire rsp_error,
    input wire rsp_ready,
    output wire mem_valid, mem_write,
    output wire [63:0] mem_addr, mem_wdata,
    output wire [7:0] mem_wstrb,
    output wire mem_rsp_ready,
    input wire mem_ready, mem_rsp_valid,
    input wire [63:0] mem_rdata,
    input wire mem_error
);
    localparam integer MAX_WORDS = READ_ONLY ? 16384 : 8192;
    localparam integer LEGAL = (LINES == 1 || LINES == 4 ||
        LINES == 16 || LINES == 64) && WORDS >= 1 && WORDS <= MAX_WORDS &&
        (READ_ONLY == 0 || READ_ONLY == 1);
    initial begin
        if (LINES != 1 && LINES != 4 && LINES != 16 && LINES != 64)
            $fatal(1, "PARAMETER ERROR: cache LINES must be 1,4,16,64");
        if (WORDS < 1 || WORDS > MAX_WORDS)
            $fatal(1, "PARAMETER ERROR: cache WORDS out of range");
        if (READ_ONLY != 0 && READ_ONLY != 1)
            $fatal(1, "PARAMETER ERROR: READ_ONLY must be 0 or 1");
    end
    generate if (LEGAL) begin : g_legal
        localparam integer IW = LINES == 1 ? 1 : $clog2(LINES);
        localparam integer AW = IW + 2;
        localparam [63:0] BASE = READ_ONLY ? 64'b0 : 64'h10000000;
        localparam [63:0] LIMIT = BASE + WORDS * (READ_ONLY ? 64'd4 : 64'd8);
        localparam [3:0] IDLE=0, LOOK=1, RESPONSE=2, WB_READ=3,
            WB_SEND=4, WB_WAIT=5, FILL_SEND=6, FILL_WAIT=7,
            FILL_STORE=8, RELOOK=9, MLOOK=10, MCHECK=11, MNEXT=12;
        reg [3:0] state;
        reg [LINES-1:0] valid, dirty;
        reg [63:0] line_base [0:LINES-1];
        reg [63:0] addr_q, wdata_q, read_q, fill_q;
        wire [63:0] ram_q;
        reg [63:0] tag_q, victim_q;
        reg [7:0] strb_q;
        reg [1:0] cmd_q, beat;
        reg [IW-1:0] index_q, scan;
        reg valid_q, dirty_q, bad_q, error_q, maintenance;
        wire accept = req_valid && req_ready;
        wire [IW-1:0] req_index = LINES == 1 ? {IW{1'b0}} :
            req_addr[IW+4:5];
        wire [IW-1:0] active_index = maintenance ? scan : index_q;
        wire [63:0] wanted_base = {addr_q[63:5],5'b0};
        wire hit = valid_q && tag_q == wanted_base;
        wire [63:0] wb_addr = victim_q + {59'b0,beat,3'b0};
        wire [63:0] refill_addr = wanted_base + {59'b0,beat,3'b0};
        wire wb_present = wb_addr >= BASE && wb_addr < LIMIT;
        wire refill_present = refill_addr >= BASE && refill_addr < LIMIT;
        wire lookup = (accept && !req_cmd[1]) || state == RELOOK ||
            state == MLOOK;
        wire [IW-1:0] lookup_index = accept ? req_index :
            (state == MLOOK ? scan : index_q);
        wire [1:0] lookup_beat = accept ? req_addr[4:3] : addr_q[4:3];
        wire [AW-1:0] lookup_addr = {lookup_index,lookup_beat};
        wire [AW-1:0] victim_addr = {active_index,beat};
        wire [AW-1:0] read_addr = state == WB_READ ? victim_addr : lookup_addr;
        wire read_enable = rst_n && (lookup || state == WB_READ);
        wire write_hit = state == LOOK && !bad_q && hit &&
            cmd_q == 2'b01 && !READ_ONLY;
        wire fill_write = state == FILL_STORE;
        wire [AW-1:0] write_addr = fill_write ? {index_q,beat} :
            {index_q,addr_q[4:3]};
        wire [63:0] write_data = fill_write ? fill_q : wdata_q;
        wire [7:0] write_mask = fill_write ? 8'hff : strb_q;
        integer n;
        assign req_ready = rst_n && state == IDLE;
        assign rsp_valid = rst_n && state == RESPONSE;
        assign rsp_rdata = rsp_valid ? read_q : 64'b0;
        assign rsp_error = rsp_valid && error_q;
        assign mem_valid = rst_n &&
            ((state == WB_SEND && wb_present) ||
             (state == FILL_SEND && refill_present));
        assign mem_write = mem_valid && state == WB_SEND;
        assign mem_addr = mem_valid ? (mem_write ? wb_addr : refill_addr) : 64'b0;
        assign mem_wdata = mem_write ? ram_q : 64'b0;
        assign mem_wstrb = mem_write ? 8'hff : 8'b0;
        assign mem_rsp_ready = rst_n && (state == WB_WAIT || state == FILL_WAIT);
        for (genvar lane = 0; lane < 8; lane = lane + 1) begin : g_lane
            (* ramstyle = "M20K", nomem2reg *)
            reg [7:0] data [0:LINES*4-1];
            reg [7:0] byte_q;
            always @(posedge clk) begin
                if (read_enable) byte_q <= data[read_addr];
                if (rst_n && (write_hit || fill_write) && write_mask[lane])
                    data[write_addr] <= write_data[lane*8 +: 8];
            end
            assign ram_q[lane*8 +: 8] = byte_q;
        end
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                state <= IDLE;
                valid <= {LINES{1'b0}};
                dirty <= {LINES{1'b0}};
                addr_q <= 64'b0;
                wdata_q <= 64'b0;
                read_q <= 64'b0;
                fill_q <= 64'b0;
                tag_q <= 64'b0;
                victim_q <= 64'b0;
                strb_q <= 8'b0;
                cmd_q <= 2'b0;
                beat <= 2'b0;
                index_q <= {IW{1'b0}};
                scan <= {IW{1'b0}};
                valid_q <= 1'b0;
                dirty_q <= 1'b0;
                bad_q <= 1'b0;
                error_q <= 1'b0;
                maintenance <= 1'b0;
                for (n = 0; n < LINES; n = n + 1) line_base[n] <= 64'b0;
            end else begin
                if (lookup) begin
                    tag_q <= line_base[lookup_index];
                    valid_q <= valid[lookup_index];
                    dirty_q <= dirty[lookup_index];
                end
                case (state)
                    IDLE: if (accept) begin
                        addr_q <= req_addr;
                        wdata_q <= req_wdata;
                        strb_q <= req_wstrb;
                        cmd_q <= req_cmd;
                        index_q <= req_index;
                        scan <= {IW{1'b0}};
                        maintenance <= req_cmd[1];
                        error_q <= 1'b0;
                        read_q <= 64'b0;
                        bad_q <= req_addr < BASE || req_addr >= LIMIT ||
                            (READ_ONLY && (|req_addr[1:0] || req_cmd == 1));
                        if (req_cmd[1]) state <= MLOOK;
                        else state <= LOOK;
                    end
                    LOOK: begin
                        if (bad_q) begin
                            error_q <= 1'b1;
                            state <= RESPONSE;
                        end else if (hit) begin
                            if (cmd_q == 0) begin
                                if (READ_ONLY)
                                    read_q <= addr_q[2] ? {32'b0,ram_q[63:32]} :
                                        {32'b0,ram_q[31:0]};
                                else read_q <= ram_q;
                            end else if (|strb_q) dirty[index_q] <= 1'b1;
                            state <= RESPONSE;
                        end else begin
                            beat <= 2'b0;
                            victim_q <= tag_q;
                            if (valid_q && dirty_q && !READ_ONLY)
                                state <= WB_READ;
                            else begin
                                valid[index_q] <= 1'b0;
                                dirty[index_q] <= 1'b0;
                                state <= FILL_SEND;
                            end
                        end
                    end
                    WB_READ: state <= WB_SEND;
                    WB_SEND: begin
                        if (!wb_present) begin
                            if (beat == 3) begin
                                dirty[active_index] <= 1'b0;
                                if (maintenance) begin
                                    if (cmd_q == 3) valid[active_index] <= 1'b0;
                                    state <= MNEXT;
                                end else begin
                                    valid[index_q] <= 1'b0;
                                    beat <= 2'b0;
                                    state <= FILL_SEND;
                                end
                            end else begin
                                beat <= beat + 2'd1;
                                state <= WB_READ;
                            end
                        end else if (mem_ready) state <= WB_WAIT;
                    end
                    WB_WAIT: if (mem_rsp_valid) begin
                        if (mem_error) begin
                            error_q <= 1'b1;
                            state <= RESPONSE;
                        end else if (beat == 3) begin
                            dirty[active_index] <= 1'b0;
                            if (maintenance) begin
                                if (cmd_q == 3) valid[active_index] <= 1'b0;
                                state <= MNEXT;
                            end else begin
                                valid[index_q] <= 1'b0;
                                beat <= 2'b0;
                                state <= FILL_SEND;
                            end
                        end else begin
                            beat <= beat + 2'd1;
                            state <= WB_READ;
                        end
                    end
                    FILL_SEND: begin
                        if (!refill_present) begin
                            fill_q <= 64'b0;
                            state <= FILL_STORE;
                        end else if (mem_ready) state <= FILL_WAIT;
                    end
                    FILL_WAIT: if (mem_rsp_valid) begin
                        if (mem_error) begin
                            error_q <= 1'b1;
                            state <= RESPONSE;
                        end else begin
                            fill_q <= mem_rdata;
                            state <= FILL_STORE;
                        end
                    end
                    FILL_STORE: begin
                        if (beat == 3) begin
                            valid[index_q] <= 1'b1;
                            dirty[index_q] <= 1'b0;
                            line_base[index_q] <= wanted_base;
                            state <= RELOOK;
                        end else begin
                            beat <= beat + 2'd1;
                            state <= FILL_SEND;
                        end
                    end
                    RELOOK: state <= LOOK;
                    MLOOK: state <= MCHECK;
                    MCHECK: begin
                        if (valid_q && dirty_q && !READ_ONLY) begin
                            victim_q <= tag_q;
                            beat <= 2'b0;
                            state <= WB_READ;
                        end else begin
                            if (cmd_q == 3) valid[scan] <= 1'b0;
                            state <= MNEXT;
                        end
                    end
                    MNEXT: begin
                        if (scan == LINES-1) state <= RESPONSE;
                        else begin
                            scan <= scan + {{(IW-1){1'b0}},1'b1};
                            state <= MLOOK;
                        end
                    end
                    RESPONSE: if (rsp_ready) state <= IDLE;
                    default: state <= IDLE;
                endcase
            end
        end
    end else begin : g_bad
        assign req_ready = 1'b0;
        assign rsp_valid = 1'b0;
        assign rsp_rdata = 64'b0;
        assign rsp_error = 1'b0;
        assign mem_valid = 1'b0;
        assign mem_write = 1'b0;
        assign mem_addr = 64'b0;
        assign mem_wdata = 64'b0;
        assign mem_wstrb = 8'b0;
        assign mem_rsp_ready = 1'b0;
    end endgenerate
endmodule
