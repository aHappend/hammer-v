module hammer_v1_decode (
    input wire [31:0] insn,
    output reg illegal, use_rs1, use_rs2, rd_we,
    output wire [4:0] rs1, rs2, rd,
    output reg [63:0] imm,
    output reg [3:0] alu_op,
    output reg a_pc, b_imm, word_op, load, store,
    output wire [2:0] size,
    output reg branch, jump, jalr,
    output wire [2:0] branch_op,
    output reg muldiv,
    output wire [2:0] m_op,
    output reg [3:0] system_cause,
    output reg system_trap
);
    assign rs1 = insn[19:15];
    assign rs2 = insn[24:20];
    assign rd = insn[11:7];
    assign size = insn[14:12];
    assign branch_op = insn[14:12];
    assign m_op = insn[14:12];
    always @* begin
        illegal = 1'b0;
        use_rs1 = 1'b0;
        use_rs2 = 1'b0;
        rd_we = 1'b0;
        imm = 64'b0;
        alu_op = 4'd0;
        a_pc = 1'b0;
        b_imm = 1'b0;
        word_op = 1'b0;
        load = 1'b0;
        store = 1'b0;
        branch = 1'b0;
        jump = 1'b0;
        jalr = 1'b0;
        muldiv = 1'b0;
        system_cause = 4'b0;
        system_trap = 1'b0;
        case (insn[6:0])
            7'h37: begin
                rd_we = 1'b1;
                b_imm = 1'b1;
                alu_op = 4'd10;
                imm = {{32{insn[31]}}, insn[31:12], 12'b0};
            end
            7'h17: begin
                rd_we = 1'b1;
                a_pc = 1'b1;
                b_imm = 1'b1;
                imm = {{32{insn[31]}}, insn[31:12], 12'b0};
            end
            7'h6f: begin
                rd_we = 1'b1;
                jump = 1'b1;
                imm = {{43{insn[31]}}, insn[31], insn[19:12],
                       insn[20], insn[30:21], 1'b0};
            end
            7'h67: begin
                rd_we = 1'b1;
                use_rs1 = 1'b1;
                jump = 1'b1;
                jalr = 1'b1;
                imm = {{52{insn[31]}}, insn[31:20]};
                if (insn[14:12] != 3'b000) illegal = 1'b1;
            end
            7'h63: begin
                use_rs1 = 1'b1;
                use_rs2 = 1'b1;
                branch = 1'b1;
                imm = {{51{insn[31]}}, insn[31], insn[7],
                       insn[30:25], insn[11:8], 1'b0};
                case (insn[14:12])
                    0,1,4,5,6,7: begin end
                    default: illegal = 1'b1;
                endcase
            end
            7'h03: begin
                use_rs1 = 1'b1;
                rd_we = 1'b1;
                b_imm = 1'b1;
                load = 1'b1;
                imm = {{52{insn[31]}}, insn[31:20]};
                if (insn[14:12] == 3'b111) illegal = 1'b1;
            end
            7'h23: begin
                use_rs1 = 1'b1;
                use_rs2 = 1'b1;
                b_imm = 1'b1;
                store = 1'b1;
                imm = {{52{insn[31]}}, insn[31:25], insn[11:7]};
                if (insn[14]) illegal = 1'b1;
            end
            7'h13, 7'h1b: begin
                use_rs1 = 1'b1;
                rd_we = 1'b1;
                b_imm = 1'b1;
                word_op = (insn[6:0] == 7'h1b);
                imm = {{52{insn[31]}}, insn[31:20]};
                case (insn[14:12])
                    0: alu_op = 4'd0;
                    2: begin alu_op = 4'd3; if (word_op) illegal = 1'b1; end
                    3: begin alu_op = 4'd4; if (word_op) illegal = 1'b1; end
                    4: begin alu_op = 4'd5; if (word_op) illegal = 1'b1; end
                    6: begin alu_op = 4'd8; if (word_op) illegal = 1'b1; end
                    7: begin alu_op = 4'd9; if (word_op) illegal = 1'b1; end
                    1: begin
                        alu_op = 4'd2;
                        if (word_op) begin
                            if (insn[31:25] != 7'b0) illegal = 1'b1;
                        end else if (insn[31:26] != 6'b0) illegal = 1'b1;
                    end
                    5: begin
                        if (insn[30]) alu_op = 4'd7;
                        else alu_op = 4'd6;
                        if (word_op) begin
                            if (insn[31:25] != 7'h00 &&
                                insn[31:25] != 7'h20) illegal = 1'b1;
                        end else if (insn[31:26] != 6'h00 &&
                                     insn[31:26] != 6'h10) illegal = 1'b1;
                    end
                    default: illegal = 1'b1;
                endcase
            end
            7'h33, 7'h3b: begin
                use_rs1 = 1'b1;
                use_rs2 = 1'b1;
                rd_we = 1'b1;
                word_op = (insn[6:0] == 7'h3b);
                if (insn[31:25] == 7'h01) begin
                    muldiv = 1'b1;
                    if (word_op && insn[14:12] != 0 && !insn[14])
                        illegal = 1'b1;
                end else begin
                    case (insn[14:12])
                        0: begin
                            if (insn[31:25] == 7'h20) alu_op = 4'd1;
                            else if (insn[31:25] == 0) alu_op = 4'd0;
                            else illegal = 1'b1;
                        end
                        1: alu_op = 4'd2;
                        2: alu_op = 4'd3;
                        3: alu_op = 4'd4;
                        4: alu_op = 4'd5;
                        5: begin
                            if (insn[31:25] == 7'h20) alu_op = 4'd7;
                            else if (insn[31:25] == 0) alu_op = 4'd6;
                            else illegal = 1'b1;
                        end
                        6: alu_op = 4'd8;
                        7: alu_op = 4'd9;
                    endcase
                    if (insn[14:12] != 0 && insn[14:12] != 5 &&
                        insn[31:25] != 0) illegal = 1'b1;
                    if (word_op && insn[14:12] != 0 &&
                        insn[14:12] != 1 && insn[14:12] != 5)
                        illegal = 1'b1;
                end
            end
            7'h0f: begin
                if (insn[14:12] != 0 || insn[11:7] != 0 ||
                    insn[19:15] != 0 || insn[31:28] != 0)
                    illegal = 1'b1;
            end
            7'h73: begin
                if (insn == 32'h00000073) begin
                    system_trap = 1'b1;
                    system_cause = 4'd11;
                end else if (insn == 32'h00100073) begin
                    system_trap = 1'b1;
                    system_cause = 4'd3;
                end else illegal = 1'b1;
            end
            default: illegal = 1'b1;
        endcase
    end
endmodule
