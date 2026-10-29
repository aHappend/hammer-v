module hammer_v3_dcache #(
    parameter integer LINES = 64,
    parameter integer WORDS = 8192
) (
    input wire clk, rst_n, req_valid,
    input wire [1:0] req_cmd,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire req_ready, rsp_valid,
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
    hammer_v3_cache #(.LINES(LINES), .WORDS(WORDS), .READ_ONLY(0)) u_cache (
        .clk(clk), .rst_n(rst_n), .req_valid(req_valid), .req_cmd(req_cmd),
        .req_addr(req_addr), .req_wdata(req_wdata), .req_wstrb(req_wstrb),
        .req_ready(req_ready), .rsp_valid(rsp_valid), .rsp_rdata(rsp_rdata),
        .rsp_error(rsp_error), .rsp_ready(rsp_ready),
        .mem_valid(mem_valid), .mem_write(mem_write), .mem_addr(mem_addr),
        .mem_wdata(mem_wdata), .mem_wstrb(mem_wstrb),
        .mem_rsp_ready(mem_rsp_ready), .mem_ready(mem_ready),
        .mem_rsp_valid(mem_rsp_valid), .mem_rdata(mem_rdata), .mem_error(mem_error)
    );
endmodule
