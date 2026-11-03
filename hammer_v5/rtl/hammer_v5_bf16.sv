module hammer_v5_bf16 (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_a, req_b,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_data
);
    localparam [3:0] IDLE=0, RESPONSE=13;
    reg [3:0] phase;
    reg [63:0] a_q, b_q;
    wire advance = rst_n && phase != IDLE && phase != RESPONSE;
    wire [31:0] products [0:3];
    wire [31:0] pairs [0:1];
    wire [31:0] total;
    genvar lane;

    assign req_ready = rst_n && phase == IDLE;
    assign rsp_valid = rst_n && phase == RESPONSE;
    assign rsp_data = rsp_valid ? {32'b0,total} : 64'b0;
    generate
        for (lane = 0; lane < 4; lane = lane + 1) begin : g_product
            hammer_v5_bf16_mul u_mul (
                .clk(clk), .rst_n(rst_n), .advance(advance),
                .a(a_q[lane*16 +: 16]), .b(b_q[lane*16 +: 16]),
                .result(products[lane])
            );
        end
        for (lane = 0; lane < 2; lane = lane + 1) begin : g_pair
            hammer_v5_fp32_add u_add (
                .clk(clk), .rst_n(rst_n), .advance(advance),
                .a(products[lane*2]), .b(products[lane*2+1]),
                .result(pairs[lane])
            );
        end
    endgenerate
    hammer_v5_fp32_add u_total (
        .clk(clk), .rst_n(rst_n), .advance(advance),
        .a(pairs[0]), .b(pairs[1]), .result(total)
    );
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            phase <= IDLE;
            a_q <= 0;
            b_q <= 0;
        end else begin
            case (phase)
                IDLE: if (req_valid) begin
                    a_q <= req_a;
                    b_q <= req_b;
                    phase <= 4'd1;
                end
                RESPONSE: if (rsp_ready) phase <= IDLE;
                default: phase <= phase + 4'd1;
            endcase
        end
    end
endmodule
