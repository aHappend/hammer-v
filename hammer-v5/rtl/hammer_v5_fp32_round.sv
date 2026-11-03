module hammer_v5_fp32_round (
    input wire sign,
    input wire signed [10:0] exponent,
    input wire [26:0] significand,
    input wire is_nan, is_inf,
    output reg [31:0] result
);
    reg [26:0] adjusted;
    reg [24:0] rounded;
    reg signed [10:0] adjusted_exp;
    reg [10:0] biased_exp;

    function automatic [26:0] shift_right_jam (
        input [26:0] value,
        input [10:0] distance
    );
        reg [26:0] mask;
        begin
            mask = 27'b0;
            if (distance >= 27)
                shift_right_jam = {26'b0,|value};
            else begin
                mask = (27'd1 << distance) - 27'd1;
                shift_right_jam = (value >> distance) |
                    {26'b0,|(value & mask)};
            end
        end
    endfunction

    always @* begin
        adjusted = significand;
        adjusted_exp = exponent;
        biased_exp = 0;
        if (exponent < -11'sd126) begin
            adjusted = shift_right_jam(significand,-11'sd126 - exponent);
            adjusted_exp = -11'sd126;
        end
        rounded = {1'b0,adjusted[26:3]} +
            {24'b0,(adjusted[2] && (|adjusted[1:0] || adjusted[3]))};
        if (rounded[24]) begin
            rounded = rounded >> 1;
            adjusted_exp = adjusted_exp + 11'sd1;
        end
        biased_exp = adjusted_exp + 11'sd127;
        if (is_nan) result = 32'h7fc00000;
        else if (is_inf || adjusted_exp > 11'sd127)
            result = {sign,8'hff,23'b0};
        else if (rounded[23:0] == 0) result = {sign,31'b0};
        else if (adjusted_exp == -11'sd126 && !rounded[23])
            result = {sign,8'b0,rounded[22:0]};
        else result = {sign,biased_exp[7:0],rounded[22:0]};
    end
endmodule
