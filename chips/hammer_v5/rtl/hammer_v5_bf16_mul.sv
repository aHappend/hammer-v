module hammer_v5_bf16_mul (
    input wire clk, rst_n, advance,
    input wire [15:0] a, b,
    output reg [31:0] result
);
    typedef struct packed {
        logic sign, is_nan, is_inf;
        logic [7:0] ma, mb;
        logic signed [10:0] ea, eb;
    } unpack_t;
    typedef struct packed {
        logic sign, is_nan, is_inf;
        logic [15:0] product;
        logic signed [10:0] exponent;
    } product_t;
    typedef struct packed {
        logic sign, is_nan, is_inf;
        logic [26:0] significand;
        logic signed [10:0] exponent;
    } normal_t;
    unpack_t unpack_q;
    product_t product_q;
    normal_t normal_q;
    wire a_inf = a[14:7] == 8'hff && a[6:0] == 0;
    wire b_inf = b[14:7] == 8'hff && b[6:0] == 0;
    wire a_zero = a[14:0] == 0;
    wire b_zero = b[14:0] == 0;
    wire invalid = (a[14:7] == 8'hff && a[6:0] != 0) ||
        (b[14:7] == 8'hff && b[6:0] != 0) ||
        (a_inf && b_zero) || (b_inf && a_zero);
    wire signed [10:0] ea = a[14:7] == 0 ?
        -11'sd126 : $signed({3'b0,a[14:7]}) - 11'sd127;
    wire signed [10:0] eb = b[14:7] == 0 ?
        -11'sd126 : $signed({3'b0,b[14:7]}) - 11'sd127;

    function automatic [4:0] leading_zeros16 (input [15:0] value);
        reg [15:0] shifted;
        reg [4:0] count;
        begin
            shifted = value;
            count = 0;
            if (shifted[15:8] == 0) begin
                shifted = shifted << 8;
                count = count + 5'd8;
            end
            if (shifted[15:12] == 0) begin
                shifted = shifted << 4;
                count = count + 5'd4;
            end
            if (shifted[15:14] == 0) begin
                shifted = shifted << 2;
                count = count + 5'd2;
            end
            if (!shifted[15]) count = count + 5'd1;
            leading_zeros16 = value == 0 ? 5'd16 : count;
        end
    endfunction

    wire [4:0] leading = leading_zeros16(product_q.product);
    wire [26:0] normalized = {11'b0,product_q.product} << (6'd11 + leading);
    wire signed [10:0] normalized_exp = $signed(product_q.exponent) +
        11'sd1 - $signed({6'b0,leading});
    wire [31:0] rounded;
    hammer_v5_fp32_round u_round (
        .sign(normal_q.sign), .exponent(normal_q.exponent),
        .significand(normal_q.significand),
        .is_nan(normal_q.is_nan), .is_inf(normal_q.is_inf), .result(rounded)
    );
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            unpack_q <= '0;
            product_q <= '0;
            normal_q <= '0;
            result <= 0;
        end else if (advance) begin
            unpack_q.sign <= a[15] ^ b[15];
            unpack_q.is_nan <= invalid;
            unpack_q.is_inf <= (a_inf || b_inf) && !invalid;
            unpack_q.ma <= {a[14:7] != 0,a[6:0]};
            unpack_q.mb <= {b[14:7] != 0,b[6:0]};
            unpack_q.ea <= ea;
            unpack_q.eb <= eb;
            product_q.sign <= unpack_q.sign;
            product_q.is_nan <= unpack_q.is_nan;
            product_q.is_inf <= unpack_q.is_inf;
            product_q.product <= unpack_q.ma * unpack_q.mb;
            product_q.exponent <= $signed(unpack_q.ea) + $signed(unpack_q.eb);
            normal_q.sign <= product_q.sign;
            normal_q.is_nan <= product_q.is_nan;
            normal_q.is_inf <= product_q.is_inf;
            normal_q.significand <= normalized;
            normal_q.exponent <= normalized_exp;
            result <= rounded;
        end
    end
endmodule
