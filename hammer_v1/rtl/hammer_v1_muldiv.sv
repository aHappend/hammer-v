module hammer_v1_muldiv (
    input wire clk, rst_n, start,
    input wire [2:0] op,
    input wire word_op,
    input wire [63:0] a, b,
    output reg busy, done,
    output reg [63:0] result,
    input wire consume
);
    reg [2:0] saved_op;
    reg saved_word, negate_product, negate_quotient, negate_remainder;
    reg zero_divisor;
    reg [6:0] count;
    reg [63:0] multiplicand, product_hi, product_lo;
    reg [63:0] divisor, quotient;
    reg [64:0] remainder;
    wire signed_div = op == 3'd4 || op == 3'd6;
    wire signed_a = op == 3'd1 || op == 3'd2 || signed_div;
    wire signed_b = op == 3'd1 || signed_div;
    wire [63:0] aw = word_op ?
        (signed_a ? {{32{a[31]}}, a[31:0]} : {32'b0, a[31:0]}) : a;
    wire [63:0] bw = word_op ?
        (signed_b ? {{32{b[31]}}, b[31:0]} : {32'b0, b[31:0]}) : b;
    wire aneg = signed_a && aw[63];
    wire bneg = signed_b && bw[63];
    wire [63:0] amag = aneg ? (~aw + 64'd1) : aw;
    wire [63:0] bmag = bneg ? (~bw + 64'd1) : bw;
    wire [64:0] mul_sum = {1'b0, product_hi} +
        (product_lo[0] ? {1'b0, multiplicand} : 65'b0);
    wire [64:0] shifted_remainder = {remainder[63:0], quotient[63]};
    wire can_subtract = shifted_remainder >= {1'b0, divisor};
    wire [64:0] subtracted_remainder =
        shifted_remainder - {1'b0, divisor};
    wire [63:0] signed_low = negate_product ?
        (~product_lo + 64'd1) : product_lo;
    wire [63:0] signed_high = negate_product ?
        (~product_hi + {63'b0, (product_lo == 0)}) : product_hi;
    wire [63:0] signed_q = zero_divisor ? 64'hffffffffffffffff :
        negate_quotient ? (~quotient + 64'd1) : quotient;
    wire [63:0] signed_r = negate_remainder ?
        (~remainder[63:0] + 64'd1) : remainder[63:0];
    wire [63:0] final_full = !saved_op[2] ?
        (saved_op == 0 ? signed_low : signed_high) :
        (saved_op[1] ? signed_r : signed_q);
    wire [63:0] final_result = saved_word ?
        {{32{final_full[31]}}, final_full[31:0]} : final_full;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 1'b0;
            done <= 1'b0;
            result <= 64'b0;
            saved_op <= 3'b0;
            saved_word <= 1'b0;
            negate_product <= 1'b0;
            negate_quotient <= 1'b0;
            negate_remainder <= 1'b0;
            zero_divisor <= 1'b0;
            count <= 7'b0;
            multiplicand <= 64'b0;
            product_hi <= 64'b0;
            product_lo <= 64'b0;
            divisor <= 64'b0;
            quotient <= 64'b0;
            remainder <= 65'b0;
        end else begin
            if (consume) done <= 1'b0;
            if (start && !busy && !done) begin
                busy <= 1'b1;
                done <= 1'b0;
                count <= 7'b0;
                saved_op <= op;
                saved_word <= word_op;
                negate_product <= aneg ^ bneg;
                negate_quotient <= aneg ^ bneg;
                negate_remainder <= aneg;
                zero_divisor <= (bmag == 0);
                product_hi <= 64'b0;
                product_lo <= amag;
                multiplicand <= bmag;
                divisor <= bmag;
                quotient <= amag;
                remainder <= 65'b0;
            end else if (busy) begin
                if (count < 7'd64) begin
                    count <= count + 7'd1;
                    if (!saved_op[2]) begin
                        product_hi <= mul_sum[64:1];
                        product_lo <= {mul_sum[0], product_lo[63:1]};
                    end else begin
                        if (can_subtract) remainder <= subtracted_remainder;
                        else remainder <= shifted_remainder;
                        quotient <= {quotient[62:0], can_subtract};
                    end
                end else begin
                    busy <= 1'b0;
                    done <= 1'b1;
                    result <= final_result;
                end
            end
        end
    end
endmodule
