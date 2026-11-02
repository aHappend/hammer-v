module hammer_v5_decompress (
    input wire [15:0] insn16,
    output wire [31:0] insn32,
    output wire illegal
);
    reg [31:0] expanded;
    reg bad;
    reg [11:0] imm;
    reg [12:0] branch_imm;
    reg [20:0] jump_imm;
    wire [4:0] rd = insn16[11:7];
    wire [4:0] rs2 = insn16[6:2];
    wire [4:0] compact_rd = {2'b01,insn16[4:2]};
    wire [4:0] compact_rs1 = {2'b01,insn16[9:7]};
    wire [11:0] signed_imm = {{6{insn16[12]}},insn16[12],insn16[6:2]};

    function automatic [31:0] encode_i (
        input [11:0] immediate,
        input [4:0] source,
        input [2:0] operation,
        input [4:0] dest,
        input [6:0] opcode
    );
        encode_i = {immediate,source,operation,dest,opcode};
    endfunction

    function automatic [31:0] encode_r (
        input [6:0] extension,
        input [4:0] source2,
        input [4:0] source1,
        input [2:0] operation,
        input [4:0] dest,
        input [6:0] opcode
    );
        encode_r = {extension,source2,source1,operation,dest,opcode};
    endfunction

    function automatic [31:0] encode_s (
        input [11:0] immediate,
        input [4:0] source2,
        input [4:0] source1,
        input [2:0] operation
    );
        encode_s = {immediate[11:5],source2,source1,operation,
            immediate[4:0],7'h23};
    endfunction

    assign insn32 = expanded;
    assign illegal = bad;
    always @* begin
        expanded = 32'h00000013;
        bad = 1'b0;
        imm = 12'b0;
        branch_imm = 13'b0;
        jump_imm = 21'b0;
        case (insn16[1:0])
            2'b00: case (insn16[15:13])
                3'b000: begin
                    imm = {2'b0,insn16[10:7],insn16[12:11],
                        insn16[5],insn16[6],2'b0};
                    bad = imm == 0;
                    expanded = encode_i(imm,5'd2,3'b000,compact_rd,7'h13);
                end
                3'b010: begin
                    imm = {5'b0,insn16[5],insn16[12:10],insn16[6],2'b0};
                    expanded = encode_i(imm,compact_rs1,3'b010,compact_rd,7'h03);
                end
                3'b011: begin
                    imm = {4'b0,insn16[6:5],insn16[12:10],3'b0};
                    expanded = encode_i(imm,compact_rs1,3'b011,compact_rd,7'h03);
                end
                3'b110: begin
                    imm = {5'b0,insn16[5],insn16[12:10],insn16[6],2'b0};
                    expanded = encode_s(imm,compact_rd,compact_rs1,3'b010);
                end
                3'b111: begin
                    imm = {4'b0,insn16[6:5],insn16[12:10],3'b0};
                    expanded = encode_s(imm,compact_rd,compact_rs1,3'b011);
                end
                default: bad = 1'b1;
            endcase
            2'b01: case (insn16[15:13])
                3'b000: begin
                    if (rd != 0 && signed_imm != 0)
                        expanded = encode_i(signed_imm,rd,3'b000,rd,7'h13);
                end
                3'b001: begin
                    bad = rd == 0;
                    expanded = encode_i(signed_imm,rd,3'b000,rd,7'h1b);
                end
                3'b010: begin
                    if (rd != 0)
                        expanded = encode_i(signed_imm,5'd0,3'b000,rd,7'h13);
                end
                3'b011: begin
                    if (rd == 2) begin
                        imm = {{2{insn16[12]}},insn16[12],insn16[4:3],
                            insn16[5],insn16[2],insn16[6],4'b0};
                        bad = imm == 0;
                        expanded = encode_i(imm,5'd2,3'b000,5'd2,7'h13);
                    end else begin
                        bad = signed_imm == 0;
                        if (rd != 0)
                            expanded = {{14{insn16[12]}},insn16[12],
                                insn16[6:2],rd,7'h37};
                    end
                end
                3'b100: case (insn16[11:10])
                    2'b00,2'b01: begin
                        imm = {1'b0,insn16[10],4'b0,insn16[12],insn16[6:2]};
                        if ({insn16[12],insn16[6:2]} != 0)
                            expanded = encode_i(imm,compact_rs1,3'b101,
                                compact_rs1,7'h13);
                    end
                    2'b10:
                        expanded = encode_i(signed_imm,compact_rs1,3'b111,
                            compact_rs1,7'h13);
                    2'b11: begin
                        if (!insn16[12]) begin
                            case (insn16[6:5])
                                2'b00: expanded = encode_r(7'h20,compact_rd,
                                    compact_rs1,3'b000,compact_rs1,7'h33);
                                2'b01: expanded = encode_r(7'h00,compact_rd,
                                    compact_rs1,3'b100,compact_rs1,7'h33);
                                2'b10: expanded = encode_r(7'h00,compact_rd,
                                    compact_rs1,3'b110,compact_rs1,7'h33);
                                2'b11: expanded = encode_r(7'h00,compact_rd,
                                    compact_rs1,3'b111,compact_rs1,7'h33);
                            endcase
                        end else begin
                            case (insn16[6:5])
                                2'b00: expanded = encode_r(7'h20,compact_rd,
                                    compact_rs1,3'b000,compact_rs1,7'h3b);
                                2'b01: expanded = encode_r(7'h00,compact_rd,
                                    compact_rs1,3'b000,compact_rs1,7'h3b);
                                default: bad = 1'b1;
                            endcase
                        end
                    end
                endcase
                3'b101: begin
                    jump_imm = {{9{insn16[12]}},insn16[12],insn16[8],
                        insn16[10:9],insn16[6],insn16[7],insn16[2],
                        insn16[11],insn16[5:3],1'b0};
                    expanded = {jump_imm[20],jump_imm[10:1],jump_imm[11],
                        jump_imm[19:12],5'd0,7'h6f};
                end
                3'b110,3'b111: begin
                    branch_imm = {{4{insn16[12]}},insn16[12],insn16[6:5],
                        insn16[2],insn16[11:10],insn16[4:3],1'b0};
                    expanded = {branch_imm[12],branch_imm[10:5],5'd0,
                        compact_rs1,2'b00,insn16[13],branch_imm[4:1],
                        branch_imm[11],7'h63};
                end
            endcase
            2'b10: case (insn16[15:13])
                3'b000: begin
                    if (rd != 0 && {insn16[12],insn16[6:2]} != 0)
                        expanded = encode_i({6'b0,insn16[12],insn16[6:2]},
                            rd,3'b001,rd,7'h13);
                end
                3'b010: begin
                    imm = {4'b0,insn16[3:2],insn16[12],insn16[6:4],2'b0};
                    bad = rd == 0;
                    expanded = encode_i(imm,5'd2,3'b010,rd,7'h03);
                end
                3'b011: begin
                    imm = {3'b0,insn16[4:2],insn16[12],insn16[6:5],3'b0};
                    bad = rd == 0;
                    expanded = encode_i(imm,5'd2,3'b011,rd,7'h03);
                end
                3'b100: begin
                    if (!insn16[12]) begin
                        if (rs2 == 0) begin
                            bad = rd == 0;
                            expanded = encode_i(12'b0,rd,3'b000,5'd0,7'h67);
                        end else if (rd != 0)
                            expanded = encode_r(7'b0,rs2,5'd0,3'b000,rd,7'h33);
                    end else if (rs2 == 0) begin
                        if (rd == 0) expanded = 32'h00100073;
                        else expanded = encode_i(12'b0,rd,3'b000,5'd1,7'h67);
                    end else if (rd != 0)
                        expanded = encode_r(7'b0,rs2,rd,3'b000,rd,7'h33);
                end
                3'b110: begin
                    imm = {4'b0,insn16[8:7],insn16[12:9],2'b0};
                    expanded = encode_s(imm,rs2,5'd2,3'b010);
                end
                3'b111: begin
                    imm = {3'b0,insn16[9:7],insn16[12:10],3'b0};
                    expanded = encode_s(imm,rs2,5'd2,3'b011);
                end
                default: bad = 1'b1;
            endcase
            default: bad = 1'b1;
        endcase
        if (bad) expanded = 32'h00000013;
    end
endmodule
