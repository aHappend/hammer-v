module hammer_v2_ram #(
    parameter integer WORDS = 8192,
    parameter integer INSTRUCTION = 0
) (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire req_write,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error,
    input wire h_req, h_write,
    input wire [31:0] h_addr,
    input wire [63:0] h_wdata,
    input wire [7:0] h_wstrb,
    output wire [63:0] h_rdata
);
    localparam integer MAX_WORDS = INSTRUCTION ? 16384 : 8192;
    localparam integer LEGAL = WORDS >= 1 && WORDS <= MAX_WORDS &&
        (INSTRUCTION == 0 || INSTRUCTION == 1);
    initial begin
        if (WORDS < 1 || WORDS > MAX_WORDS)
            $fatal(1, "PARAMETER ERROR: backing WORDS out of range");
        if (INSTRUCTION != 0 && INSTRUCTION != 1)
            $fatal(1, "PARAMETER ERROR: INSTRUCTION must be 0 or 1");
    end
    generate if (LEGAL) begin : g_legal
        localparam integer IW = WORDS <= 1 ? 1 : $clog2(WORDS);
        localparam [63:0] BASE = INSTRUCTION ? 64'b0 : 64'h10000000;
        localparam [63:0] BYTES = WORDS * (INSTRUCTION ? 64'd4 : 64'd8);
        reg pending, response, error_q, host_valid;
        wire bad = req_addr < BASE || req_addr >= BASE + BYTES ||
            |req_addr[2:0] || (INSTRUCTION && req_write);
        wire host_bad = {32'b0,h_addr} >= BYTES ||
            (INSTRUCTION ? (|h_addr[1:0] || |h_wdata[63:32] ||
                           |h_wstrb[7:4]) : |h_addr[2:0]);
        wire accept = req_valid && req_ready;
        wire host_accept = rst_n && h_req && !host_bad;
        wire [63:0] offset = req_addr - BASE;
        wire [63:0] read_data, host_data;
        assign req_ready = rst_n && !pending && !response && !h_req;
        assign rsp_valid = rst_n && response;
        assign rsp_error = rsp_valid && error_q;
        assign rsp_rdata = rsp_valid && !error_q ? read_data : 64'b0;
        assign h_rdata = rst_n && host_valid ? host_data : 64'b0;
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                pending <= 1'b0;
                response <= 1'b0;
                error_q <= 1'b0;
                host_valid <= 1'b0;
            end else begin
                if (rsp_valid && rsp_ready) response <= 1'b0;
                if (pending) begin
                    pending <= 1'b0;
                    response <= 1'b1;
                end
                if (accept) begin
                    pending <= 1'b1;
                    error_q <= bad;
                end
                host_valid <= host_accept;
            end
        end
        if (INSTRUCTION) begin : g_imem
            localparam integer ROWS = (WORDS + 1) >> 1;
            localparam integer RW = ROWS <= 1 ? 1 : $clog2(ROWS);
            wire [63:0] bank_data;
            reg upper_q, host_odd_q;
            wire core_read = rst_n && accept && !bad;
            wire [RW-1:0] ri = ROWS == 1 ? {RW{1'b0}} : offset[RW+2:3];
            wire [RW-1:0] hi = ROWS == 1 ? {RW{1'b0}} : h_addr[RW+2:3];
            wire upper_present = offset + 64'd4 < BYTES;
            wire [RW-1:0] port_index = host_accept ? hi : ri;
            always @(posedge clk) begin
                if (core_read) upper_q <= upper_present;
                if (host_accept) host_odd_q <= h_addr[2];
            end
            for (genvar bank = 0; bank < 2; bank = bank + 1) begin : g_bank
                localparam integer BANK_WORDS = (WORDS + 1 - bank) >> 1;
                if (BANK_WORDS > 0) begin : g_present
                    wire host_select = host_accept && h_addr[2] == (bank == 1);
                    wire read_enable = host_select ||
                        (core_read && (bank == 0 || upper_present));
                    for (genvar lane = 0; lane < 4; lane = lane + 1) begin : g_lane
                        (* ramstyle = "M20K", nomem2reg *)
                        reg [7:0] mem [0:BANK_WORDS-1];
                        reg [7:0] read_q;
                        always @(posedge clk) begin
                            if (read_enable) read_q <= mem[port_index];
                            if (host_select && h_write && h_wstrb[lane])
                                mem[port_index] <= h_wdata[lane*8 +: 8];
                        end
                        assign bank_data[bank*32+lane*8 +: 8] = read_q;
                    end
                end else begin : g_absent
                    assign bank_data[bank*32 +: 32] = 32'b0;
                end
            end
            assign read_data = {upper_q ? bank_data[63:32] : 32'b0,bank_data[31:0]};
            assign host_data = {32'b0,host_odd_q ? bank_data[63:32] : bank_data[31:0]};
        end else begin : g_dmem
            wire [63:0] read_q;
            wire [IW-1:0] ri = WORDS == 1 ? {IW{1'b0}} : offset[IW+2:3];
            wire [IW-1:0] hi = WORDS == 1 ? {IW{1'b0}} : h_addr[IW+2:3];
            wire host_write = host_accept && h_write;
            wire core_write = rst_n && accept && !bad && req_write;
            wire [IW-1:0] port_index = host_accept ? hi : ri;
            wire [63:0] wd = host_write ? h_wdata : req_wdata;
            wire [7:0] ws = host_write ? h_wstrb : req_wstrb;
            wire read_enable = host_accept || (rst_n && accept && !bad);
            for (genvar lane = 0; lane < 8; lane = lane + 1) begin : g_lane
                (* ramstyle = "M20K", nomem2reg *)
                reg [7:0] mem [0:WORDS-1];
                reg [7:0] byte_q;
                always @(posedge clk) begin
                    if (read_enable) byte_q <= mem[port_index];
                    if ((host_write || core_write) && ws[lane])
                        mem[port_index] <= wd[lane*8 +: 8];
                end
                assign read_q[lane*8 +: 8] = byte_q;
            end
            assign read_data = read_q;
            assign host_data = read_q;
        end
    end else begin : g_bad
        assign req_ready = 1'b0;
        assign rsp_valid = 1'b0;
        assign rsp_error = 1'b0;
        assign rsp_rdata = 64'b0;
        assign h_rdata = 64'b0;
    end endgenerate
endmodule
