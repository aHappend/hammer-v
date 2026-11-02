module hammer_v2_alu (
    input wire [63:0] a, b,
    input wire [3:0] op,
    input wire word_op,
    output wire [63:0] result
);
    reg [63:0] full_result;
    reg [31:0] word_result;
    always @* begin
        case (op)
            0: full_result = a + b;
            1: full_result = a - b;
            2: full_result = a << b[5:0];
            3: full_result = {63'b0, ($signed(a) < $signed(b))};
            4: full_result = {63'b0, (a < b)};
            5: full_result = a ^ b;
            6: full_result = a >> b[5:0];
            7: full_result = $signed(a) >>> b[5:0];
            8: full_result = a | b;
            9: full_result = a & b;
            10: full_result = b;
            default: full_result = 64'b0;
        endcase
        case (op)
            0: word_result = a[31:0] + b[31:0];
            1: word_result = a[31:0] - b[31:0];
            2: word_result = a[31:0] << b[4:0];
            6: word_result = a[31:0] >> b[4:0];
            7: word_result = $signed(a[31:0]) >>> b[4:0];
            default: word_result = full_result[31:0];
        endcase
    end
    assign result = word_op ? {{32{word_result[31]}}, word_result} : full_result;
endmodule
