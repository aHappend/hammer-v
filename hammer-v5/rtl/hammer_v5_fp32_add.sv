module hammer_v5_fp32_add (
    input wire clk, rst_n, advance,
    input wire [31:0] a, b,
    output reg [31:0] result
);
    typedef struct packed {
        logic sign, zero_sign, subtract, is_nan, is_inf;
        logic [26:0] larger_sig, smaller_sig;
        logic signed [10:0] exponent;
    } aligned_t;
    typedef struct packed {
        logic sign, zero_sign, is_nan, is_inf;
        logic [27:0] magnitude;
        logic signed [10:0] exponent;
    } sum_t;
    typedef struct packed {
        logic sign, is_nan, is_inf;
        logic [26:0] significand;
        logic signed [10:0] exponent;
    } normal_t;
    aligned_t aligned_q;
    sum_t sum_q;
    normal_t normal_q;
    normal_t normal_next;
    wire choose_a = a[30:0] >= b[30:0];
    wire [31:0] larger_bits = choose_a ? a : b;
    wire [31:0] smaller_bits = choose_a ? b : a;
    wire [8:0] large_exp = larger_bits[30:23] == 0 ?
        9'd1 : {1'b0,larger_bits[30:23]};
    wire [8:0] small_exp = smaller_bits[30:23] == 0 ?
        9'd1 : {1'b0,smaller_bits[30:23]};
    wire [26:0] large_sig = {larger_bits[30:23] != 0,larger_bits[22:0],3'b0};
    wire [26:0] small_sig = {smaller_bits[30:23] != 0,smaller_bits[22:0],3'b0};
    wire a_inf = a[30:23] == 8'hff && a[22:0] == 0;
    wire b_inf = b[30:23] == 8'hff && b[22:0] == 0;
    wire invalid = (a[30:23] == 8'hff && a[22:0] != 0) ||
        (b[30:23] == 8'hff && b[22:0] != 0) ||
        (a_inf && b_inf && (a[31] != b[31]));

    function automatic [26:0] shift_right_jam (
        input [26:0] value,
        input [8:0] distance
    );
        reg [26:0] mask;
        begin
            mask = 0;
            if (distance >= 27)
                shift_right_jam = {26'b0,|value};
            else begin
                mask = (27'd1 << distance) - 27'd1;
                shift_right_jam = (value >> distance) |
                    {26'b0,|(value & mask)};
            end
        end
    endfunction

    function automatic [5:0] leading_zeros32 (input [31:0] value);
        reg [31:0] shifted;
        reg [5:0] count;
        begin
            shifted = value;
            count = 0;
            if (shifted[31:16] == 0) begin
                shifted = shifted << 16;
                count = count + 6'd16;
            end
            if (shifted[31:24] == 0) begin
                shifted = shifted << 8;
                count = count + 6'd8;
            end
            if (shifted[31:28] == 0) begin
                shifted = shifted << 4;
                count = count + 6'd4;
            end
            if (shifted[31:30] == 0) begin
                shifted = shifted << 2;
                count = count + 6'd2;
            end
            if (!shifted[31]) count = count + 6'd1;
            leading_zeros32 = value == 0 ? 6'd32 : count;
        end
    endfunction

    wire [26:0] aligned_small = shift_right_jam(small_sig,large_exp-small_exp);
    wire [5:0] leading = leading_zeros32({sum_q.magnitude[26:0],5'b0});
    wire [31:0] rounded;
    hammer_v5_fp32_round u_round (
        .sign(normal_q.sign), .exponent(normal_q.exponent),
        .significand(normal_q.significand),
        .is_nan(normal_q.is_nan), .is_inf(normal_q.is_inf), .result(rounded)
    );
    always @* begin
        normal_next = '0;
        normal_next.sign = sum_q.sign;
        normal_next.is_nan = sum_q.is_nan;
        normal_next.is_inf = sum_q.is_inf;
        normal_next.exponent = sum_q.exponent;
        if (sum_q.magnitude[27]) begin
            normal_next.significand = sum_q.magnitude[27:1] |
                {26'b0,sum_q.magnitude[0]};
            normal_next.exponent = $signed(sum_q.exponent) + 11'sd1;
        end else if (sum_q.magnitude != 0) begin
            normal_next.significand = sum_q.magnitude[26:0] << leading;
            normal_next.exponent = $signed(sum_q.exponent) -
                $signed({5'b0,leading});
        end else if (!sum_q.is_nan && !sum_q.is_inf) begin
            normal_next.sign = sum_q.zero_sign;
        end
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            aligned_q <= '0;
            sum_q <= '0;
            normal_q <= '0;
            result <= 0;
        end else if (advance) begin
            aligned_q.sign <= larger_bits[31];
            aligned_q.zero_sign <= a[31] && b[31];
            aligned_q.subtract <= a[31] ^ b[31];
            aligned_q.is_nan <= invalid;
            aligned_q.is_inf <= (a_inf || b_inf) && !invalid;
            aligned_q.larger_sig <= large_sig;
            aligned_q.smaller_sig <= aligned_small;
            aligned_q.exponent <= $signed({2'b0,large_exp}) - 11'sd127;
            sum_q.sign <= aligned_q.sign;
            sum_q.zero_sign <= aligned_q.zero_sign;
            sum_q.is_nan <= aligned_q.is_nan;
            sum_q.is_inf <= aligned_q.is_inf;
            if (aligned_q.subtract)
                sum_q.magnitude <= {1'b0,aligned_q.larger_sig} -
                    {1'b0,aligned_q.smaller_sig};
            else
                sum_q.magnitude <= {1'b0,aligned_q.larger_sig} +
                    {1'b0,aligned_q.smaller_sig};
            sum_q.exponent <= aligned_q.exponent;
            normal_q <= normal_next;
            result <= rounded;
        end
    end
endmodule
