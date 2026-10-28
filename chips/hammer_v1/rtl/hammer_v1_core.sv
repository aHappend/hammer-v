module hammer_v1_core #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16
) (
    input wire clk, rst_n, start,
    output wire halted,
    input wire [4:0] dbg_raddr,
    output wire [63:0] dbg_rdata,
    output reg trap_valid,
    output reg [63:0] trap_pc, trap_cause,
    output reg retire_valid,
    output reg [63:0] retire_pc, retire_next_pc,
    output reg [31:0] retire_insn,
    output reg retire_rd_we,
    output reg [4:0] retire_rd,
    output reg [63:0] retire_rd_data,
    output reg retire_mem_valid, retire_mem_write,
    output reg [63:0] retire_mem_addr,
    output reg [7:0] retire_mem_wmask,
    output reg [63:0] retire_mem_wdata, retire_mem_rdata,
    output wire stall_load_use, stall_mem, stall_muldiv,
    output wire redirect_valid,
    output wire [63:0] redirect_pc,
    output wire ex_valid,
    output wire [63:0] ex_pc,
    output wire [1:0] ex_rs1_sel, ex_rs2_sel, ex_store_sel,
    output wire i_req,
    output wire [63:0] i_addr,
    input wire [31:0] i_data,
    input wire i_error,
    output wire d_req, d_write,
    output wire [63:0] d_addr, d_wdata,
    output wire [7:0] d_wstrb,
    input wire [63:0] d_rdata,
    output wire a_valid,
    input wire a_ready,
    output wire a_write,
    output wire [31:0] a_addr,
    output wire [63:0] a_wdata,
    output wire [7:0] a_wstrb,
    input wire a_rsp_valid,
    output wire a_rsp_ready,
    input wire [63:0] a_rdata,
    input wire a_error
);
    localparam [63:0] DMEM_END = 64'h10000000 + DMEM_WORDS * 64'd8;
    reg running;
    reg [63:0] fetch_pc;
    reg id_v;
    reg [63:0] id_pc;
    reg x_v, x_fault;
    reg [63:0] x_pc, x_pred, x_a, x_b, x_imm;
    reg [31:0] x_insn;
    reg [3:0] x_cause, x_alu_op;
    reg [4:0] x_rs1, x_rs2, x_rd;
    reg x_use1, x_use2, x_we, x_a_pc, x_b_imm, x_word;
    reg x_load, x_store, x_branch, x_jump, x_jalr, x_muldiv;
    reg [2:0] x_size, x_branch_op, x_m_op;
    reg x_m_started;
    reg m_v, m_fault;
    reg [3:0] m_cause;
    reg [63:0] m_pc, m_next, m_result, m_addr, m_wdata;
    reg [31:0] m_insn;
    reg [4:0] m_rd;
    reg m_we, m_load, m_store, m_mmio, m_sent;
    reg [2:0] m_size;
    reg [7:0] m_wmask;
    reg w_v, w_fault;
    reg [3:0] w_cause;
    reg [63:0] w_pc, w_next, w_result, w_addr, w_wdata;
    reg [31:0] w_insn;
    reg [4:0] w_rd;
    reg w_we, w_load, w_store, w_dmem;
    reg [2:0] w_size;
    reg [7:0] w_wmask;

    wire dec_illegal, dec_use1, dec_use2, dec_we;
    wire [4:0] dec_rs1, dec_rs2, dec_rd;
    wire [63:0] dec_imm;
    wire [3:0] dec_alu, dec_cause;
    wire dec_a_pc, dec_b_imm, dec_word, dec_load, dec_store;
    wire dec_branch, dec_jump, dec_jalr, dec_muldiv, dec_trap;
    wire [2:0] dec_size, dec_branch_op, dec_m_op;
    hammer_v1_decode u_decode (
        .insn(i_data), .illegal(dec_illegal),
        .use_rs1(dec_use1), .use_rs2(dec_use2), .rd_we(dec_we),
        .rs1(dec_rs1), .rs2(dec_rs2), .rd(dec_rd), .imm(dec_imm),
        .alu_op(dec_alu), .a_pc(dec_a_pc), .b_imm(dec_b_imm),
        .word_op(dec_word), .load(dec_load), .store(dec_store),
        .size(dec_size), .branch(dec_branch), .jump(dec_jump),
        .jalr(dec_jalr), .branch_op(dec_branch_op), .muldiv(dec_muldiv),
        .m_op(dec_m_op), .system_cause(dec_cause), .system_trap(dec_trap)
    );

    function automatic [63:0] extend_load;
        input [63:0] data;
        input [2:0] offset;
        input [2:0] kind;
        reg [63:0] shifted;
        begin
            shifted = data >> {offset, 3'b000};
            case (kind)
                0: extend_load = {{56{shifted[7]}}, shifted[7:0]};
                1: extend_load = {{48{shifted[15]}}, shifted[15:0]};
                2: extend_load = {{32{shifted[31]}}, shifted[31:0]};
                3: extend_load = shifted;
                4: extend_load = {56'b0, shifted[7:0]};
                5: extend_load = {48'b0, shifted[15:0]};
                6: extend_load = {32'b0, shifted[31:0]};
                default: extend_load = 64'b0;
            endcase
        end
    endfunction

    wire [63:0] wb_data = w_load && w_dmem ?
        extend_load(d_rdata, w_addr[2:0], w_size) : w_result;
    wire terminal = rst_n && running && w_v && w_fault;
    wire wb_commit = rst_n && running && w_v && !w_fault;
    wire wb_we = wb_commit && w_we && w_rd != 0;
    wire [63:0] rf_a, rf_b;
    hammer_v1_regfile u_regfile (
        .clk(clk), .rst_n(rst_n), .rs1(dec_rs1), .rs2(dec_rs2),
        .rdata1(rf_a), .rdata2(rf_b),
        .we(wb_we), .rd(w_rd), .wdata(wb_data),
        .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata)
    );

    wire interlock;
    wire [1:0] sel1, sel2, store_sel;
    hammer_v1_hazard u_hazard (
        .id_use1(dec_use1 && id_v), .id_use2(dec_use2 && id_v),
        .id_rs1(dec_rs1), .id_rs2(dec_rs2),
        .ex_load(x_v && x_load && !x_fault),
        .ex_we(x_we), .ex_rd(x_rd), .ex_use1(x_use1 && x_v),
        .ex_use2(x_use2 && x_v), .ex_rs1(x_rs1), .ex_rs2(x_rs2),
        .mem_we(m_v && m_we && !m_fault),
        .mem_ready_result(!m_load), .mem_rd(m_rd),
        .wb_we(wb_we), .wb_rd(w_rd),
        .interlock(interlock), .sel1(sel1), .sel2(sel2),
        .store_sel(store_sel)
    );
    wire [63:0] forward_a = sel1 == 2'b10 ? m_result :
                                sel1 == 2'b01 ? wb_data : x_a;
    wire [63:0] forward_b = sel2 == 2'b10 ? m_result :
                                sel2 == 2'b01 ? wb_data : x_b;
    wire [63:0] alu_a = x_a_pc ? x_pc : forward_a;
    wire [63:0] alu_b = x_b_imm ? x_imm : forward_b;
    wire [63:0] alu_result;
    hammer_v1_alu u_alu (
        .a(alu_a), .b(alu_b), .op(x_alu_op),
        .word_op(x_word), .result(alu_result)
    );
    reg branch_taken;
    always @* begin
        case (x_branch_op)
            0: branch_taken = forward_a == forward_b;
            1: branch_taken = forward_a != forward_b;
            4: branch_taken = $signed(forward_a) < $signed(forward_b);
            5: branch_taken = $signed(forward_a) >= $signed(forward_b);
            6: branch_taken = forward_a < forward_b;
            7: branch_taken = forward_a >= forward_b;
            default: branch_taken = 1'b0;
        endcase
    end
    wire control_taken = x_jump || (x_branch && branch_taken);
    wire [63:0] relative_target = x_pc + x_imm;
    wire [63:0] indirect_target = (forward_a + x_imm) & 64'hfffffffffffffffe;
    wire [63:0] control_target = x_jalr ? indirect_target : relative_target;
    wire [63:0] actual_next = control_taken ? control_target : x_pc + 64'd4;
    wire [63:0] effective_addr = forward_a + x_imm;
    wire addr_dmem = effective_addr >= 64'h10000000 &&
                     effective_addr < DMEM_END;
    wire addr_mmio = effective_addr >= 64'h40000000 &&
                     effective_addr <= 64'h4000ffff;
    reg data_misaligned;
    reg [7:0] base_mask;
    always @* begin
        case (x_size[1:0])
            0: begin data_misaligned = 1'b0; base_mask = 8'h01; end
            1: begin data_misaligned = effective_addr[0]; base_mask = 8'h03; end
            2: begin data_misaligned = |effective_addr[1:0]; base_mask = 8'h0f; end
            3: begin data_misaligned = |effective_addr[2:0]; base_mask = 8'hff; end
        endcase
    end
    reg ex_fault_now;
    reg [3:0] ex_cause_now;
    always @* begin
        ex_fault_now = x_fault;
        ex_cause_now = x_cause;
        if (!x_fault) begin
            if (control_taken && control_target[1:0] != 0) begin
                ex_fault_now = 1'b1;
                ex_cause_now = 4'd0;
            end else if ((x_load || x_store) && data_misaligned) begin
                ex_fault_now = 1'b1;
                if (x_store) ex_cause_now = 4'd6;
                else ex_cause_now = 4'd4;
            end else if ((x_load || x_store) && !addr_dmem && !addr_mmio) begin
                ex_fault_now = 1'b1;
                if (x_store) ex_cause_now = 4'd7;
                else ex_cause_now = 4'd5;
            end
        end
    end

    wire mem_bus_error = m_v && m_mmio && m_sent && a_rsp_valid && a_error;
    wire mem_fault_now = m_v && (m_fault || mem_bus_error);
    wire [3:0] mem_cause_now = m_fault ? m_cause :
                                            (m_store ? 4'd7 : 4'd5);
    wire mem_advance = rst_n && running && m_v && !terminal &&
        (m_fault || !m_mmio || (m_sent && a_rsp_valid));
    wire mem_ready = !m_v || mem_advance;
    wire older_fault = terminal || mem_fault_now;
    wire md_busy, md_done;
    wire [63:0] md_result;
    wire md_start = rst_n && running && x_v && x_muldiv && !x_m_started &&
                    !ex_fault_now && !older_fault;
    wire ex_complete = ex_fault_now || !x_muldiv || md_done;
    wire ex_advance = rst_n && running && x_v && ex_complete &&
                      mem_ready && !older_fault;
    wire ex_ready = (!x_v || ex_advance) && mem_ready;
    wire redirect = ex_advance && !ex_fault_now && actual_next != x_pred;
    wire ex_fault_transfer = ex_advance && ex_fault_now;
    wire id_advance = rst_n && running && id_v && ex_ready &&
                      !interlock && !older_fault && !redirect &&
                      !ex_fault_transfer;
    wire fetch_accept = rst_n && running && (!id_v || id_advance) &&
                        mem_ready && !older_fault && !redirect &&
                        !ex_fault_transfer && !(x_v && x_fault);

    hammer_v1_muldiv u_muldiv (
        .clk(clk), .rst_n(rst_n), .start(md_start), .op(x_m_op),
        .word_op(x_word), .a(forward_a), .b(forward_b),
        .busy(md_busy), .done(md_done), .result(md_result),
        .consume(ex_advance && x_muldiv && !ex_fault_now)
    );
    wire [63:0] predicted_next;
    hammer_v1_predictor #(.PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES))
    u_predictor (
        .clk(clk), .rst_n(rst_n), .pc(id_pc), .insn(i_data),
        .next_pc(predicted_next),
        .update(ex_advance && !ex_fault_now && (x_branch || x_jump)),
        .update_pc(x_pc), .update_target(control_target),
        .update_taken(control_taken), .update_conditional(x_branch)
    );
    assign halted = !rst_n || !running;
    assign i_req = fetch_accept;
    assign i_addr = fetch_accept ? (id_v ? predicted_next : fetch_pc) : 64'b0;
    assign d_req = mem_advance && !mem_fault_now && !m_mmio &&
                   (m_load || m_store);
    assign d_write = d_req && m_store;
    assign d_addr = d_req ? m_addr : 64'b0;
    assign d_wdata = d_req && m_store ? m_wdata : 64'b0;
    assign d_wstrb = d_req && m_store ? m_wmask : 8'b0;
    assign a_valid = rst_n && running && m_v && m_mmio && !m_fault &&
                     !m_sent && !terminal;
    assign a_write = a_valid && m_store;
    assign a_addr = a_valid ? {m_addr[31:3], 3'b000} : 32'b0;
    assign a_wdata = a_valid && m_store ? m_wdata : 64'b0;
    assign a_wstrb = a_valid && m_store ? m_wmask : 8'b0;
    assign a_rsp_ready = mem_advance && m_mmio && m_sent;
    assign stall_load_use = rst_n && running && id_v && interlock &&
                            !older_fault && !redirect;
    assign stall_mem = rst_n && running && m_v && !mem_advance && !terminal;
    assign stall_muldiv = rst_n && running && x_v && x_muldiv &&
                          !ex_complete && !older_fault;
    assign redirect_valid = redirect;
    assign redirect_pc = redirect ? actual_next : 64'b0;
    assign ex_valid = rst_n && running && x_v && !older_fault;
    assign ex_pc = ex_valid ? x_pc : 64'b0;
    assign ex_rs1_sel = ex_valid && !x_fault ? sel1 : 2'b00;
    assign ex_rs2_sel = ex_valid && !x_fault ? sel2 : 2'b00;
    assign ex_store_sel = ex_valid && x_store && !x_fault ? store_sel : 2'b00;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            running <= 1'b0;
            fetch_pc <= 64'b0;
            id_v <= 1'b0;
            id_pc <= 64'b0;
            x_v <= 1'b0;
            x_fault <= 1'b0;
            x_pc <= 64'b0;
            x_pred <= 64'b0;
            x_a <= 64'b0;
            x_b <= 64'b0;
            x_imm <= 64'b0;
            x_insn <= 32'b0;
            x_cause <= 4'b0;
            x_alu_op <= 4'b0;
            x_rs1 <= 5'b0;
            x_rs2 <= 5'b0;
            x_rd <= 5'b0;
            x_use1 <= 1'b0;
            x_use2 <= 1'b0;
            x_we <= 1'b0;
            x_a_pc <= 1'b0;
            x_b_imm <= 1'b0;
            x_word <= 1'b0;
            x_load <= 1'b0;
            x_store <= 1'b0;
            x_branch <= 1'b0;
            x_jump <= 1'b0;
            x_jalr <= 1'b0;
            x_muldiv <= 1'b0;
            x_size <= 3'b0;
            x_branch_op <= 3'b0;
            x_m_op <= 3'b0;
            x_m_started <= 1'b0;
            m_v <= 1'b0;
            m_fault <= 1'b0;
            m_cause <= 4'b0;
            m_pc <= 64'b0;
            m_next <= 64'b0;
            m_result <= 64'b0;
            m_addr <= 64'b0;
            m_wdata <= 64'b0;
            m_insn <= 32'b0;
            m_rd <= 5'b0;
            m_we <= 1'b0;
            m_load <= 1'b0;
            m_store <= 1'b0;
            m_mmio <= 1'b0;
            m_sent <= 1'b0;
            m_size <= 3'b0;
            m_wmask <= 8'b0;
            w_v <= 1'b0;
            w_fault <= 1'b0;
            w_cause <= 4'b0;
            w_pc <= 64'b0;
            w_next <= 64'b0;
            w_result <= 64'b0;
            w_addr <= 64'b0;
            w_wdata <= 64'b0;
            w_insn <= 32'b0;
            w_rd <= 5'b0;
            w_we <= 1'b0;
            w_load <= 1'b0;
            w_store <= 1'b0;
            w_dmem <= 1'b0;
            w_size <= 3'b0;
            w_wmask <= 8'b0;
            trap_valid <= 1'b0;
            trap_pc <= 64'b0;
            trap_cause <= 64'b0;
            retire_valid <= 1'b0;
            retire_pc <= 64'b0;
            retire_next_pc <= 64'b0;
            retire_insn <= 32'b0;
            retire_rd_we <= 1'b0;
            retire_rd <= 5'b0;
            retire_rd_data <= 64'b0;
            retire_mem_valid <= 1'b0;
            retire_mem_write <= 1'b0;
            retire_mem_addr <= 64'b0;
            retire_mem_wmask <= 8'b0;
            retire_mem_wdata <= 64'b0;
            retire_mem_rdata <= 64'b0;
        end else begin
            retire_valid <= 1'b0;
            retire_pc <= 64'b0;
            retire_next_pc <= 64'b0;
            retire_insn <= 32'b0;
            retire_rd_we <= 1'b0;
            retire_rd <= 5'b0;
            retire_rd_data <= 64'b0;
            retire_mem_valid <= 1'b0;
            retire_mem_write <= 1'b0;
            retire_mem_addr <= 64'b0;
            retire_mem_wmask <= 8'b0;
            retire_mem_wdata <= 64'b0;
            retire_mem_rdata <= 64'b0;
            if (wb_commit) begin
                retire_valid <= 1'b1;
                retire_pc <= w_pc;
                retire_next_pc <= w_next;
                retire_insn <= w_insn;
                if (wb_we) begin
                    retire_rd_we <= 1'b1;
                    retire_rd <= w_rd;
                    retire_rd_data <= wb_data;
                end
                if (w_load || w_store) begin
                    retire_mem_valid <= 1'b1;
                    retire_mem_write <= w_store;
                    retire_mem_addr <= w_addr;
                    if (w_store) begin
                        retire_mem_wmask <= w_wmask;
                        retire_mem_wdata <= w_wdata;
                    end else retire_mem_rdata <= wb_data;
                end
            end
            if (terminal) begin
                running <= 1'b0;
                trap_valid <= 1'b1;
                trap_pc <= w_pc;
                trap_cause <= {60'b0, w_cause};
                id_v <= 1'b0;
                x_v <= 1'b0;
                m_v <= 1'b0;
                w_v <= 1'b0;
            end else if (!running) begin
                if (start && !trap_valid) begin
                    running <= 1'b1;
                    fetch_pc <= 64'b0;
                    id_v <= 1'b0;
                    x_v <= 1'b0;
                    m_v <= 1'b0;
                    w_v <= 1'b0;
                end
            end else begin
                w_v <= mem_advance;
                if (mem_advance) begin
                    w_fault <= mem_fault_now;
                    w_cause <= mem_cause_now;
                    w_pc <= m_pc;
                    w_next <= m_next;
                    w_insn <= m_insn;
                    w_rd <= m_rd;
                    w_we <= m_we && !mem_fault_now;
                    w_load <= m_load && !mem_fault_now;
                    w_store <= m_store && !mem_fault_now;
                    w_dmem <= !m_mmio;
                    w_size <= m_size;
                    w_addr <= m_addr;
                    w_wdata <= m_wdata;
                    w_wmask <= m_wmask;
                    if (m_load && m_mmio)
                        w_result <= extend_load(a_rdata, m_addr[2:0], m_size);
                    else w_result <= m_result;
                end
                if (mem_advance) begin
                    m_v <= 1'b0;
                    m_sent <= 1'b0;
                end
                if (a_valid && a_ready) m_sent <= 1'b1;
                if (ex_advance) begin
                    m_v <= 1'b1;
                    m_fault <= ex_fault_now;
                    m_cause <= ex_cause_now;
                    m_pc <= x_pc;
                    m_next <= actual_next;
                    m_insn <= x_insn;
                    m_rd <= x_rd;
                    m_we <= x_we && !ex_fault_now;
                    m_load <= x_load && !ex_fault_now;
                    m_store <= x_store && !ex_fault_now;
                    m_mmio <= (x_load || x_store) && addr_mmio && !ex_fault_now;
                    m_sent <= 1'b0;
                    m_size <= x_size;
                    m_addr <= effective_addr;
                    m_wdata <= forward_b << {effective_addr[2:0], 3'b000};
                    m_wmask <= base_mask << effective_addr[2:0];
                    if (x_jump) m_result <= x_pc + 64'd4;
                    else if (x_muldiv) m_result <= md_result;
                    else m_result <= alu_result;
                    x_v <= 1'b0;
                end else if (x_v) begin
                    x_a <= forward_a;
                    x_b <= forward_b;
                end
                if (md_start) x_m_started <= 1'b1;
                if (id_advance) begin
                    x_v <= 1'b1;
                    x_pc <= id_pc;
                    x_insn <= i_data;
                    x_pred <= predicted_next;
                    x_a <= rf_a;
                    x_b <= rf_b;
                    x_rs1 <= dec_rs1;
                    x_rs2 <= dec_rs2;
                    x_rd <= dec_rd;
                    x_use1 <= dec_use1;
                    x_use2 <= dec_use2;
                    x_we <= dec_we;
                    x_imm <= dec_imm;
                    x_alu_op <= dec_alu;
                    x_a_pc <= dec_a_pc;
                    x_b_imm <= dec_b_imm;
                    x_word <= dec_word;
                    x_load <= dec_load;
                    x_store <= dec_store;
                    x_branch <= dec_branch;
                    x_jump <= dec_jump;
                    x_jalr <= dec_jalr;
                    x_muldiv <= dec_muldiv;
                    x_size <= dec_size;
                    x_branch_op <= dec_branch_op;
                    x_m_op <= dec_m_op;
                    x_m_started <= 1'b0;
                    x_fault <= i_error || dec_illegal || dec_trap;
                    if (i_error) begin
                        if (id_pc[1:0] != 0) x_cause <= 4'd0;
                        else x_cause <= 4'd1;
                    end else if (dec_illegal) x_cause <= 4'd2;
                    else x_cause <= dec_cause;
                    id_v <= 1'b0;
                end
                if (fetch_accept) begin
                    id_v <= 1'b1;
                    id_pc <= i_addr;
                    fetch_pc <= i_addr + 64'd4;
                end
                if (redirect) begin
                    id_v <= 1'b0;
                    fetch_pc <= actual_next;
                end
                if (ex_fault_transfer) id_v <= 1'b0;
                if (mem_fault_now) begin
                    id_v <= 1'b0;
                    x_v <= 1'b0;
                end
            end
        end
    end
endmodule
