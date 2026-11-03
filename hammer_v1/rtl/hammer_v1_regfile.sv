module hammer_v1_regfile (
    input wire clk, rst_n,
    input wire [4:0] rs1, rs2,
    output wire [63:0] rdata1, rdata2,
    input wire we,
    input wire [4:0] rd,
    input wire [63:0] wdata,
    input wire [4:0] dbg_raddr,
    output wire [63:0] dbg_rdata
);
    reg [63:0] regs [1:31];
    integer n;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (n = 1; n < 32; n = n + 1) regs[n] <= 64'b0;
        end else if (we && rd != 0) regs[rd] <= wdata;
    end
    assign rdata1 = !rst_n || rs1 == 0 ? 64'b0 :
                    we && rd == rs1 && rd != 0 ? wdata : regs[rs1];
    assign rdata2 = !rst_n || rs2 == 0 ? 64'b0 :
                    we && rd == rs2 && rd != 0 ? wdata : regs[rs2];
    assign dbg_rdata = !rst_n || dbg_raddr == 0 ? 64'b0 : regs[dbg_raddr];
endmodule
