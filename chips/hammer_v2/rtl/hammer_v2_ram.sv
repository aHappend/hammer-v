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
            (* ramstyle = "M20K", nomem2reg *) reg [31:0] mem [0:WORDS-1];
            reg [31:0] low_q, high_q, host_q;
            reg upper_q;
            wire [IW-1:0] ri = WORDS == 1 ? {IW{1'b0}} : offset[IW+1:2];
            wire [IW-1:0] hi = WORDS == 1 ? {IW{1'b0}} : h_addr[IW+1:2];
            wire upper_present = offset + 64'd4 < BYTES;
            wire [IW-1:0] ri_upper = ri + {{(IW-1){1'b0}},1'b1};
            integer lane;
            always @(posedge clk) begin
                if (rst_n && accept && !bad) begin
                    low_q <= mem[ri];
                    upper_q <= upper_present;
                    if (upper_present) high_q <= mem[ri_upper];
                end
                if (host_accept) begin
                    host_q <= mem[hi];
                    if (h_write)
                        for (lane = 0; lane < 4; lane = lane + 1)
                            if (h_wstrb[lane])
                                mem[hi][lane*8 +: 8] <= h_wdata[lane*8 +: 8];
                end
            end
            assign read_data = {upper_q ? high_q : 32'b0,low_q};
            assign host_data = {32'b0,host_q};
        end else begin : g_dmem
            (* ramstyle = "M20K", nomem2reg *) reg [63:0] mem [0:WORDS-1];
            reg [63:0] read_q, host_q;
            wire [IW-1:0] ri = WORDS == 1 ? {IW{1'b0}} : offset[IW+2:3];
            wire [IW-1:0] hi = WORDS == 1 ? {IW{1'b0}} : h_addr[IW+2:3];
            wire host_write = host_accept && h_write;
            wire core_write = rst_n && accept && !bad && req_write;
            wire [IW-1:0] wi = host_write ? hi : ri;
            wire [63:0] wd = host_write ? h_wdata : req_wdata;
            wire [7:0] ws = host_write ? h_wstrb : req_wstrb;
            integer lane;
            always @(posedge clk) begin
                if (rst_n && accept && !bad) read_q <= mem[ri];
                if (host_accept) host_q <= mem[hi];
                if (host_write || core_write)
                    for (lane = 0; lane < 8; lane = lane + 1)
                        if (ws[lane]) mem[wi][lane*8 +: 8] <= wd[lane*8 +: 8];
            end
            assign read_data = read_q;
            assign host_data = host_q;
        end
    end else begin : g_bad
        assign req_ready = 1'b0;
        assign rsp_valid = 1'b0;
        assign rsp_error = 1'b0;
        assign rsp_rdata = 64'b0;
        assign h_rdata = 64'b0;
    end endgenerate
endmodule
