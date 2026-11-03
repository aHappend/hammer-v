module hammer_v2_hazard (
    input wire id_use1, id_use2,
    input wire [4:0] id_rs1, id_rs2,
    input wire ex_load, ex_we,
    input wire [4:0] ex_rd,
    input wire ex_use1, ex_use2,
    input wire [4:0] ex_rs1, ex_rs2,
    input wire mem_we, mem_ready_result,
    input wire [4:0] mem_rd,
    input wire wb_we,
    input wire [4:0] wb_rd,
    output wire interlock,
    output wire [1:0] sel1, sel2, store_sel
);
    assign interlock = ex_load && ex_we && ex_rd != 0 &&
        ((id_use1 && id_rs1 == ex_rd) || (id_use2 && id_rs2 == ex_rd));
    assign sel1 = !ex_use1 || ex_rs1 == 0 ? 2'b00 :
        mem_we && mem_ready_result && mem_rd != 0 && mem_rd == ex_rs1 ? 2'b10 :
        wb_we && wb_rd != 0 && wb_rd == ex_rs1 ? 2'b01 : 2'b00;
    assign sel2 = !ex_use2 || ex_rs2 == 0 ? 2'b00 :
        mem_we && mem_ready_result && mem_rd != 0 && mem_rd == ex_rs2 ? 2'b10 :
        wb_we && wb_rd != 0 && wb_rd == ex_rs2 ? 2'b01 : 2'b00;
    assign store_sel = sel2;
endmodule
