module hammer_v2_dmem #(
    parameter integer WORDS = 8192
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
    hammer_v2_ram #(.WORDS(WORDS), .INSTRUCTION(0)) u_ram (
        .clk(clk), .rst_n(rst_n), .req_valid(req_valid), .req_ready(req_ready),
        .req_write(req_write), .req_addr(req_addr), .req_wdata(req_wdata),
        .req_wstrb(req_wstrb), .rsp_valid(rsp_valid), .rsp_ready(rsp_ready),
        .rsp_rdata(rsp_rdata), .rsp_error(rsp_error),
        .h_req(h_req), .h_write(h_write), .h_addr(h_addr),
        .h_wdata(h_wdata), .h_wstrb(h_wstrb), .h_rdata(h_rdata)
    );
endmodule
