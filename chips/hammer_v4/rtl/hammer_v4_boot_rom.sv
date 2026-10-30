module hammer_v4_boot_rom (
    input wire [4:0] word_addr,
    output reg [31:0] word_data
);
    always @* begin
        case (word_addr)
            5'd0: word_data = 32'h00000513;
            5'd1: word_data = 32'h043f05b7;
            5'd2: word_data = 32'h00559593;
            5'd3: word_data = 32'h00100293;
            5'd4: word_data = 32'h01f29293;
            5'd5: word_data = 32'h00028067;
            default: word_data = 32'h00000013;
        endcase
    end
endmodule
