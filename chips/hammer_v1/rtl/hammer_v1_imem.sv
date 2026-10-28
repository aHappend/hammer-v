module hammer_v1_imem #(
    parameter integer WORDS = 16384
) (
    input wire clk, rst_n,
    input wire i_req,
    input wire [63:0] i_addr,
    output wire [31:0] i_data,
    output wire i_error,
    input wire h_req, h_write,
    input wire [31:0] h_addr,
    input wire [63:0] h_wdata,
    input wire [7:0] h_wstrb,
    output wire [63:0] h_rdata
);
    localparam integer N = WORDS >= 1 && WORDS <= 16384 ? WORDS : 1;
    localparam integer IW = N <= 1 ? 1 : $clog2(N);
    localparam [63:0] LIMIT = N * 64'd4;
    (* ramstyle = "M20K", nomem2reg *) reg [31:0] mem [0:N-1];
    reg [31:0] iq, hq;
    reg error_q, i_valid, h_valid;
    wire i_bad = i_addr[1:0] != 0 || i_addr >= LIMIT;
    wire [IW-1:0] ii = N == 1 ? {IW{1'b0}} : i_addr[IW+1:2];
    wire [IW-1:0] hi = N == 1 ? {IW{1'b0}} : h_addr[IW+1:2];
    integer lane;
    always @(posedge clk) begin
        if (rst_n) begin
            if (i_req && !i_bad) iq <= mem[ii];
            if (h_req) begin
                hq <= mem[hi];
                if (h_write)
                    for (lane = 0; lane < 4; lane = lane + 1)
                        if (h_wstrb[lane])
                            mem[hi][lane*8 +: 8] <= h_wdata[lane*8 +: 8];
            end
        end
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            error_q <= 1'b0;
            i_valid <= 1'b0;
            h_valid <= 1'b0;
        end else begin
            if (i_req) begin
                error_q <= i_bad;
                i_valid <= 1'b1;
            end
            if (h_req) h_valid <= 1'b1;
        end
    end
    assign i_data = rst_n && i_valid && !error_q ? iq : 32'b0;
    assign i_error = rst_n && i_valid && error_q;
    assign h_rdata = rst_n && h_valid ? {32'b0, hq} : 64'b0;
endmodule
