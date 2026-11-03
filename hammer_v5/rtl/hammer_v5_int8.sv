module hammer_v5_int8 (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_a, req_b, req_seed,
    input wire req_square,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_data
);
    localparam [3:0] IDLE=0, OPERANDS=1, PRODUCTS=2, PAIRS=3,
        PARTIALS=4, REDUCTION=5, RESULT=6, RESPONSE=7;
    reg [3:0] state;
    reg [63:0] a_q, b_q, seed_q, result_q;
    reg square_q;
    reg signed [7:0] lane_a [0:7];
    reg signed [7:0] lane_b [0:7];
    reg signed [15:0] product [0:7];
    reg signed [16:0] pair_sum [0:3];
    reg signed [17:0] partial_sum [0:1];
    reg signed [18:0] reduction_q;
    integer n;

    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_data = rsp_valid ? result_q : 64'b0;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            a_q <= 0;
            b_q <= 0;
            seed_q <= 0;
            result_q <= 0;
            square_q <= 0;
            reduction_q <= 0;
            for (n = 0; n < 8; n = n + 1) begin
                lane_a[n] <= 0;
                lane_b[n] <= 0;
                product[n] <= 0;
            end
            for (n = 0; n < 4; n = n + 1) pair_sum[n] <= 0;
            for (n = 0; n < 2; n = n + 1) partial_sum[n] <= 0;
        end else begin
            case (state)
                IDLE: if (req_valid) begin
                    a_q <= req_a;
                    b_q <= req_b;
                    seed_q <= req_square ? req_seed : 64'b0;
                    square_q <= req_square;
                    state <= OPERANDS;
                end
                OPERANDS: begin
                    for (n = 0; n < 8; n = n + 1) begin
                        lane_a[n] <= a_q[n*8 +: 8];
                        lane_b[n] <= square_q ? a_q[n*8 +: 8] : b_q[n*8 +: 8];
                    end
                    state <= PRODUCTS;
                end
                PRODUCTS: begin
                    for (n = 0; n < 8; n = n + 1)
                        product[n] <= lane_a[n] * lane_b[n];
                    state <= PAIRS;
                end
                PAIRS: begin
                    for (n = 0; n < 4; n = n + 1)
                        pair_sum[n] <=
                            {product[2*n][15],product[2*n]} +
                            {product[2*n+1][15],product[2*n+1]};
                    state <= PARTIALS;
                end
                PARTIALS: begin
                    for (n = 0; n < 2; n = n + 1)
                        partial_sum[n] <=
                            {pair_sum[2*n][16],pair_sum[2*n]} +
                            {pair_sum[2*n+1][16],pair_sum[2*n+1]};
                    state <= REDUCTION;
                end
                REDUCTION: begin
                    reduction_q <=
                        {partial_sum[0][17],partial_sum[0]} +
                        {partial_sum[1][17],partial_sum[1]};
                    state <= RESULT;
                end
                RESULT: begin
                    result_q <= seed_q + {{45{reduction_q[18]}},reduction_q};
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
