module hammer_v1_dmem #(
    parameter integer WORDS = 8192
) (
    input wire clk, rst_n,
    input wire d_req, d_write,
    input wire [63:0] d_addr, d_wdata,
    input wire [7:0] d_wstrb,
    output wire [63:0] d_rdata,
    input wire h_req, h_write,
    input wire [31:0] h_addr,
    input wire [63:0] h_wdata,
    input wire [7:0] h_wstrb,
    output wire [63:0] h_rdata
);
    localparam integer N = WORDS >= 1 && WORDS <= 8192 ? WORDS : 1;
    localparam integer IW = N <= 1 ? 1 : $clog2(N);
    (* ramstyle = "M20K", nomem2reg *) reg [63:0] mem [0:N-1];
    reg [63:0] dq, hq;
    reg d_valid, h_valid;
    wire [IW-1:0] di = N == 1 ? {IW{1'b0}} : d_addr[IW+2:3];
    wire [IW-1:0] hi = N == 1 ? {IW{1'b0}} : h_addr[IW+2:3];
    integer d_lane, h_lane;
    // Independent RAM ports; top-level ownership excludes host/CPU collisions.
    always @(posedge clk) begin
        if (rst_n && d_req) begin
            dq <= mem[di];
            if (d_write)
                for (d_lane = 0; d_lane < 8; d_lane = d_lane + 1)
                    if (d_wstrb[d_lane])
                        mem[di][d_lane*8 +: 8] <= d_wdata[d_lane*8 +: 8];
        end
    end
    always @(posedge clk) begin
        if (rst_n && h_req) begin
            hq <= mem[hi];
            if (h_write)
                for (h_lane = 0; h_lane < 8; h_lane = h_lane + 1)
                    if (h_wstrb[h_lane])
                        mem[hi][h_lane*8 +: 8] <= h_wdata[h_lane*8 +: 8];
        end
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            d_valid <= 1'b0;
            h_valid <= 1'b0;
        end else begin
            if (d_req) d_valid <= 1'b1;
            if (h_req) h_valid <= 1'b1;
        end
    end
    assign d_rdata = rst_n && d_valid ? dq : 64'b0;
    assign h_rdata = rst_n && h_valid ? hq : 64'b0;
endmodule
