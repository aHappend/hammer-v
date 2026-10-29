module hammer_v2_core #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16,
    parameter integer LEGACY_TRAPS = 0
) (
    input wire clk, rst_n, start, halt_req,
    input wire host_data_write,
    input wire irq_msip, irq_mtip, irq_meip, irq_seip,
    input wire [63:0] mtime,
    output wire halted,
    input wire [4:0] dbg_raddr,
    output wire [63:0] dbg_rdata,
    output reg trap_valid,
    output reg [63:0] trap_pc, trap_cause, trap_tval,
    output reg [1:0] trap_target_priv,
    output reg trap_interrupt,
    output reg retire_valid,
    output reg [63:0] retire_pc, retire_next_pc,
    output reg [31:0] retire_insn,
    output reg [1:0] retire_priv,
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
    output wire i_req_valid,
    input wire i_req_ready,
    output wire [1:0] i_req_cmd,
    output wire [63:0] i_req_addr,
    input wire i_rsp_valid,
    output wire i_rsp_ready,
    input wire [63:0] i_rsp_rdata,
    input wire i_rsp_error,
    output wire d_req_valid,
    input wire d_req_ready,
    output wire [1:0] d_req_cmd,
    output wire [63:0] d_req_addr, d_req_wdata,
    output wire [7:0] d_req_wstrb,
    input wire d_rsp_valid,
    output wire d_rsp_ready,
    input wire [63:0] d_rsp_rdata,
    input wire d_rsp_error,
    output wire a_valid,
    input wire a_ready,
    output wire a_write,
    output wire [31:0] a_addr,
    output wire [63:0] a_wdata,
    output wire [7:0] a_wstrb,
    input wire a_rsp_valid,
    output wire a_rsp_ready,
    input wire [63:0] a_rdata,
    input wire a_error,
    output wire c_req_valid,
    input wire c_req_ready,
    output wire c_req_write,
    output wire [1:0] c_req_size,
    output wire [63:0] c_req_addr, c_req_wdata,
    output wire [7:0] c_req_wstrb,
    input wire c_rsp_valid,
    output wire c_rsp_ready,
    input wire [63:0] c_rsp_rdata,
    input wire c_rsp_error
);
    initial begin
        if (IMEM_WORDS < 1 || IMEM_WORDS > 16384)
            $fatal(1, "PARAMETER ERROR: IMEM_WORDS must be 1..16384");
        if (DMEM_WORDS < 1 || DMEM_WORDS > 8192)
            $fatal(1, "PARAMETER ERROR: DMEM_WORDS must be 1..8192");
        if (LEGACY_TRAPS != 0 && LEGACY_TRAPS != 1)
            $fatal(1, "PARAMETER ERROR: LEGACY_TRAPS must be 0 or 1");
    end
    localparam [63:0] DMEM_END = 64'h10000000 + DMEM_WORDS * 64'd8;
    typedef struct packed {
        logic [63:0] pc, pred, a, b, imm;
        logic [31:0] insn;
        logic [1:0] priv;
        logic fault;
        logic [3:0] cause;
        logic [63:0] tval;
        logic [4:0] rs1, rs2, rd;
        logic use1, use2, we, a_pc, b_imm, word_op;
        logic [3:0] alu;
        logic load, store, branch, jump, jalr, muldiv;
        logic [2:0] size, branch_op, m_op;
        logic csr, atomic, fence, fence_i, mret, sret, wfi, sfence;
        logic special, md_started;
    } execute_t;
    typedef struct packed {
        logic [63:0] pc, next_pc, result, addr, wdata, src, tval;
        logic [31:0] insn;
        logic [1:0] priv;
        logic [4:0] rd;
        logic we, fault;
        logic [3:0] cause;
        logic [7:0] mask;
        logic [2:0] size;
        logic load, store, mmio, clint;
        logic csr, atomic, fence, fence_i, mret, sret, wfi, sfence, special;
        logic sent, atom_started;
        logic [1:0] phase;
    } memory_t;
    typedef struct packed {
        logic [63:0] pc, next_pc, result, addr, wdata, rdata, src, tval;
        logic [31:0] insn;
        logic [1:0] priv;
        logic [4:0] rd;
        logic we, fault;
        logic [3:0] cause;
        logic [7:0] mask;
        logic mem_valid, mem_write;
        logic csr, mret, sret, wfi, special;
    } writeback_t;
    reg running, stopping, sleeping, legacy_stop;
    reg [1:0] halt_phase;
    reg [63:0] fetch_pc, committed_next, fetch_context;
    reg fetch_busy, fetch_kill;
    reg id_v, id_error, x_v, m_v, w_v;
    reg [63:0] id_pc, id_pred;
    reg [31:0] id_insn;
    typedef struct packed {
        logic [63:0] pc, pred;
        logic [31:0] insn;
        logic error;
    } fetch_t;
    fetch_t fetch_queue [0:3];
    wire [160:0] queue_head_bits;
    fetch_t queue_head;
    reg [1:0] queue_read, queue_write;
    reg [2:0] queue_count;
    reg queue_release;
    reg redirect_event;
    reg [63:0] redirect_event_pc;
    execute_t x;
    memory_t m;
    writeback_t w;
    wire dec_illegal, dec_use1, dec_use2, dec_we;
    wire [4:0] dec_rs1, dec_rs2, dec_rd;
    wire [63:0] dec_imm;
    wire [3:0] dec_alu, dec_cause;
    wire dec_a_pc, dec_b_imm, dec_word, dec_load, dec_store;
    wire dec_branch, dec_jump, dec_jalr, dec_muldiv, dec_trap;
    wire [2:0] dec_size, dec_branch_op, dec_m_op;
    wire dec_csr, dec_atomic, dec_fence, dec_fence_i;
    wire dec_mret, dec_sret, dec_wfi, dec_sfence;
    hammer_v2_decode u_decode (
        .insn(id_insn), .illegal(dec_illegal), .use_rs1(dec_use1),
        .use_rs2(dec_use2), .rd_we(dec_we), .rs1(dec_rs1), .rs2(dec_rs2),
        .rd(dec_rd), .imm(dec_imm), .alu_op(dec_alu), .a_pc(dec_a_pc),
        .b_imm(dec_b_imm), .word_op(dec_word), .load(dec_load), .store(dec_store),
        .size(dec_size), .branch(dec_branch), .jump(dec_jump), .jalr(dec_jalr),
        .branch_op(dec_branch_op), .muldiv(dec_muldiv), .m_op(dec_m_op),
        .system_cause(dec_cause), .system_trap(dec_trap),
        .csr(dec_csr), .atomic(dec_atomic), .fence(dec_fence), .fence_i(dec_fence_i),
        .mret(dec_mret), .sret(dec_sret), .wfi(dec_wfi), .sfence(dec_sfence)
    );
    function automatic [63:0] extend_load (
        input [63:0] data,
        input [2:0] offset,
        input [2:0] kind
    );
        reg [63:0] shifted;
        begin
            shifted = data >> {offset,3'b0};
            case (kind)
                0: extend_load = {{56{shifted[7]}},shifted[7:0]};
                1: extend_load = {{48{shifted[15]}},shifted[15:0]};
                2: extend_load = {{32{shifted[31]}},shifted[31:0]};
                3: extend_load = shifted;
                4: extend_load = {56'b0,shifted[7:0]};
                5: extend_load = {48'b0,shifted[15:0]};
                6: extend_load = {32'b0,shifted[31:0]};
                default: extend_load = 64'b0;
            endcase
        end
    endfunction

    wire [1:0] current_priv;
    wire [63:0] status, csr_mie, csr_mip, csr_medeleg, csr_mideleg;
    wire [63:0] csr_mtvec, csr_stvec, csr_mepc, csr_sepc, csr_data, return_pc;
    wire csr_illegal, return_illegal;
    wire [1:0] return_kind = w_v && w.mret ? 2'd1 :
        w_v && w.sret ? 2'd2 : 2'd0;
    wire csr_read = !(w.insn[13:12] == 1 && w.rd == 0);
    wire csr_write = w.insn[13:12] == 1 || w.insn[19:15] != 0;
    wire [63:0] csr_source = w.insn[14] ? {59'b0,w.insn[19:15]} : w.src;
    wire wb_sync = rst_n && running && w_v &&
        (w.fault || (w.csr && csr_illegal) ||
         ((w.mret || w.sret) && return_illegal));
    wire [63:0] sync_cause = w.fault ? {60'b0,w.cause} : 64'd2;
    wire [63:0] sync_tval = w.fault ? w.tval : {32'b0,w.insn};
    wire wb_commit = rst_n && running && w_v && !wb_sync;
    wire [63:0] wb_data = w.csr ? csr_data : w.result;
    wire wb_we = wb_commit && w.we && w.rd != 0;
    wire [63:0] wb_next = w.mret || w.sret ? return_pc : w.next_pc;
    wire trap_enter, trap_is_interrupt, trap_wake;
    wire [1:0] trap_destination;
    wire [63:0] entry_epc, entry_cause, entry_tval, entry_vector;
    wire pipeline_empty = !id_v && !x_v && !m_v && !w_v && queue_count == 0;
    wire interrupt_boundary = running && pipeline_empty && !fetch_busy &&
        !stopping && !halt_req && !legacy_stop;
    wire halt_clean_fault = rst_n && running && stopping && pipeline_empty &&
        !fetch_busy && halt_phase == 2 && d_rsp_valid && d_rsp_error;
    hammer_v2_csr u_csr (
        .clk(clk), .rst_n(rst_n), .csr_valid(running && w_v && w.csr),
        .csr_commit(wb_commit && w.csr), .csr_addr(w.insn[31:20]),
        .csr_op(w.insn[14:12]), .csr_src(csr_source),
        .csr_read(csr_read), .csr_write(csr_write),
        .csr_rdata(csr_data), .csr_illegal(csr_illegal), .retire(wb_commit),
        .mtime(mtime), .irq_msip(irq_msip), .irq_mtip(irq_mtip),
        .irq_meip(irq_meip), .irq_seip(irq_seip),
        .return_kind(return_kind), .return_commit(wb_commit && (w.mret || w.sret)),
        .return_illegal(return_illegal), .return_pc(return_pc),
        .trap_enter(trap_enter), .trap_target(trap_destination),
        .trap_epc(entry_epc), .trap_cause(entry_cause), .trap_tval(entry_tval),
        .priv(current_priv), .mstatus(status), .mie(csr_mie), .mip(csr_mip),
        .medeleg(csr_medeleg), .mideleg(csr_mideleg),
        .mtvec(csr_mtvec), .stvec(csr_stvec), .mepc(csr_mepc), .sepc(csr_sepc)
    );
    hammer_v2_trap u_trap (
        .rst_n(rst_n), .priv(current_priv), .mstatus(status),
        .mie(csr_mie), .mip(csr_mip), .medeleg(csr_medeleg),
        .mideleg(csr_mideleg), .mtvec(csr_mtvec), .stvec(csr_stvec),
        .sync_valid(wb_sync || halt_clean_fault),
        .sync_pc(halt_clean_fault ? committed_next : w.pc),
        .sync_cause(halt_clean_fault ? 64'd7 : sync_cause),
        .sync_tval(halt_clean_fault ? 64'b0 : sync_tval), .boundary_valid(interrupt_boundary),
        .boundary_pc(committed_next), .enter(trap_enter),
        .interrupt(trap_is_interrupt), .target_priv(trap_destination),
        .epc(entry_epc), .cause(entry_cause), .tval(entry_tval),
        .vector(entry_vector), .wake(trap_wake)
    );
    wire [63:0] local_pending = csr_mie & csr_mip & 64'haaa;
    wire machine_enabled = current_priv < 3 || status[3];
    wire supervisor_enabled = current_priv < 1 ||
        (current_priv == 1 && status[1]);
    wire irq_stop = |(local_pending & ~csr_mideleg & {64{machine_enabled}}) ||
        |(local_pending & csr_mideleg & {64{supervisor_enabled}});
    wire [63:0] rf_a, rf_b;
    hammer_v2_regfile u_regfile (
        .clk(clk), .rst_n(rst_n), .rs1(dec_rs1), .rs2(dec_rs2),
        .rdata1(rf_a), .rdata2(rf_b), .we(wb_we),
        .rd(w.rd), .wdata(wb_data), .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata)
    );
    wire interlock;
    wire [1:0] sel1, sel2, store_sel;
    hammer_v2_hazard u_hazard (
        .id_use1(dec_use1 && id_v), .id_use2(dec_use2 && id_v),
        .id_rs1(dec_rs1), .id_rs2(dec_rs2),
        .ex_load(x_v && x.load && !x.fault), .ex_we(x.we), .ex_rd(x.rd),
        .ex_use1(x_v && x.use1), .ex_use2(x_v && x.use2),
        .ex_rs1(x.rs1), .ex_rs2(x.rs2),
        .mem_we(m_v && m.we && !m.fault),
        .mem_ready_result(!m.load && !m.atomic && !m.csr), .mem_rd(m.rd),
        .wb_we(wb_we), .wb_rd(w.rd), .interlock(interlock),
        .sel1(sel1), .sel2(sel2), .store_sel(store_sel)
    );
    wire [63:0] forward_a = sel1 == 2'b10 ? m.result :
        sel1 == 2'b01 ? wb_data : x.a;
    wire [63:0] forward_b = sel2 == 2'b10 ? m.result :
        sel2 == 2'b01 ? wb_data : x.b;
    wire [63:0] alu_result;
    hammer_v2_alu u_alu (
        .a(x.a_pc ? x.pc : forward_a), .b(x.b_imm ? x.imm : forward_b),
        .op(x.alu), .word_op(x.word_op), .result(alu_result)
    );
    reg branch_taken;
    always @* begin
        case (x.branch_op)
            0: branch_taken = forward_a == forward_b;
            1: branch_taken = forward_a != forward_b;
            4: branch_taken = $signed(forward_a) < $signed(forward_b);
            5: branch_taken = $signed(forward_a) >= $signed(forward_b);
            6: branch_taken = forward_a < forward_b;
            7: branch_taken = forward_a >= forward_b;
            default: branch_taken = 1'b0;
        endcase
    end
    wire control_taken = x.jump || (x.branch && branch_taken);
    wire [63:0] control_target = x.jalr ?
        ((forward_a + x.imm) & 64'hfffffffffffffffe) : x.pc + x.imm;
    wire [63:0] actual_next = control_taken ? control_target : x.pc + 64'd4;
    wire [63:0] effective_addr = x.atomic ? forward_a : forward_a + x.imm;
    wire addr_dmem = effective_addr >= 64'h10000000 && effective_addr < DMEM_END;
    wire addr_mmio = effective_addr >= 64'h40000000 &&
        effective_addr <= 64'h4000ffff;
    wire addr_clint = (effective_addr >= 64'h02000000 &&
        effective_addr < 64'h02000004) ||
        (effective_addr >= 64'h02004000 && effective_addr < 64'h02004008) ||
        (effective_addr >= 64'h0200bff8 && effective_addr < 64'h0200c000);
    reg misaligned;
    reg [7:0] base_mask;
    always @* begin
        case (x.size[1:0])
            0: begin misaligned = 1'b0; base_mask = 8'h01; end
            1: begin misaligned = effective_addr[0]; base_mask = 8'h03; end
            2: begin misaligned = |effective_addr[1:0]; base_mask = 8'h0f; end
            default: begin misaligned = |effective_addr[2:0]; base_mask = 8'hff; end
        endcase
    end
    reg ex_fault;
    reg [3:0] ex_cause;
    reg [63:0] ex_tval;
    always @* begin
        ex_fault = x.fault;
        ex_cause = x.cause;
        ex_tval = x.tval;
        if (!x.fault) begin
            if ((x.wfi && current_priv != 3 && status[21]) ||
                (x.sfence && (current_priv == 0 ||
                             (current_priv == 1 && status[20])))) begin
                ex_fault = 1'b1;
                ex_cause = 4'd2;
                ex_tval = {32'b0,x.insn};
            end else if (control_taken && |control_target[1:0]) begin
                ex_fault = 1'b1;
                ex_cause = 4'd0;
                ex_tval = control_target;
            end else if ((x.load || x.store || x.atomic) && misaligned) begin
                ex_fault = 1'b1;
                ex_cause = (x.store || (x.atomic && x.insn[31:27] != 2)) ?
                    4'd6 : 4'd4;
                ex_tval = effective_addr;
            end else if ((x.load || x.store || x.atomic) &&
                (!addr_dmem && (x.atomic || (!addr_mmio && !addr_clint)))) begin
                ex_fault = 1'b1;
                ex_cause = (x.store || (x.atomic && x.insn[31:27] != 2)) ?
                    4'd7 : 4'd5;
                ex_tval = effective_addr;
            end
        end
    end

    wire atom_ready, atom_done, atom_error, atom_write;
    wire [3:0] atom_cause;
    wire [63:0] atom_tval, atom_result, atom_old, atom_wdata;
    wire [7:0] atom_mask;
    wire atom_req_valid, atom_rsp_ready;
    wire [1:0] atom_req_cmd;
    wire [63:0] atom_req_addr, atom_req_wdata;
    wire [7:0] atom_req_wstrb;
    wire halt_clean = running && stopping && pipeline_empty && !fetch_busy;
    wire halt_complete = halt_clean && halt_phase == 2 && d_rsp_valid &&
        !d_rsp_error;
    wire atom_start = rst_n && running && m_v && m.atomic && !m.fault &&
        !m.atom_started && !w_v && !trap_enter && atom_ready;
    wire mem_advance;
    hammer_v2_atomic #(.DMEM_WORDS(DMEM_WORDS)) u_atomic (
        .clk(clk), .rst_n(rst_n), .start(atom_start), .ready(atom_ready),
        .op(m.insn[31:27]), .word_op(m.insn[14:12] == 2),
        .addr(m.addr), .operand(m.src),
        .invalidate(trap_enter || halt_complete || host_data_write),
        .store_commit(wb_commit && w.mem_write), .store_addr(w.addr),
        .done(atom_done), .consume(mem_advance && m.atomic),
        .error(atom_error), .cause(atom_cause), .tval(atom_tval),
        .result(atom_result), .old_data(atom_old), .mem_write(atom_write),
        .wmask(atom_mask), .wdata(atom_wdata),
        .req_valid(atom_req_valid), .req_ready(d_req_ready && m_v && m.atomic),
        .req_cmd(atom_req_cmd), .req_addr(atom_req_addr),
        .req_wdata(atom_req_wdata), .req_wstrb(atom_req_wstrb),
        .rsp_valid(d_rsp_valid && m_v && m.atomic),
        .rsp_ready(atom_rsp_ready), .rsp_rdata(d_rsp_rdata), .rsp_error(d_rsp_error)
    );
    wire mem_request = rst_n && running && m_v && !m.fault && !m.sent &&
        !trap_enter && (!w_v || wb_commit) && (m.load || m.store);
    wire normal_d_request = mem_request && !m.mmio && !m.clint;
    wire fence_d_request = rst_n && running && m_v && m.fence &&
        !m.fault && m.phase == 0 && !w_v && !trap_enter;
    wire fence_i_request = rst_n && running && m_v && m.fence_i &&
        !m.fault && m.phase == 2 && !fetch_busy && !trap_enter;
    wire halt_d_request = rst_n && halt_clean && halt_phase == 0;
    wire selected_rsp_valid = m.mmio ? a_rsp_valid :
        m.clint ? c_rsp_valid : d_rsp_valid;
    wire selected_rsp_error = m.mmio ? a_error :
        m.clint ? c_rsp_error : d_rsp_error;
    wire [63:0] selected_rsp_data = m.mmio ? a_rdata :
        m.clint ? c_rsp_rdata : d_rsp_rdata;
    wire memory_done = (m.load || m.store) && m.sent && selected_rsp_valid;
    wire fence_d_done = m.fence && m.phase == 1 && d_rsp_valid;
    wire fence_i_done = m.fence_i && m.phase == 3 && i_rsp_valid;
    wire fence_done = fence_d_done && (d_rsp_error || !m.fence_i) || fence_i_done;
    wire mem_error_now = memory_done && selected_rsp_error ||
        fence_d_done && d_rsp_error || fence_i_done && i_rsp_error ||
        m.atomic && m.atom_started && atom_done && atom_error;
    wire mem_fault_now = m_v && (m.fault || mem_error_now);
    wire [3:0] mem_cause_now = m.fault ? m.cause :
        m.atomic ? atom_cause : m.load ? 4'd5 : 4'd7;
    wire [63:0] mem_tval_now = m.fault ? m.tval :
        m.atomic ? atom_tval : m.addr;
    wire mem_complete = m.fault ||
        (m.atomic ? (m.atom_started && atom_done) :
         m.fence ? fence_done :
         (m.load || m.store) ? memory_done : 1'b1);
    assign mem_advance = rst_n && running && m_v && mem_complete && !trap_enter;
    wire mem_ready = !m_v || mem_advance;
    wire older_fault = trap_enter || mem_fault_now;
    wire md_busy, md_done;
    wire [63:0] md_result;
    wire md_start = rst_n && running && x_v && x.muldiv && !x.md_started &&
        !ex_fault && !m_v && (!w_v || wb_commit) && !older_fault;
    wire ex_complete = ex_fault || !x.muldiv || md_done;
    wire x_serial = x.special || ((x.load || x.store) && (addr_mmio || addr_clint));
    wire ex_advance = rst_n && running && x_v && ex_complete && mem_ready &&
        !older_fault && (!x_serial || (!m_v && !w_v));
    wire ex_ready = (!x_v || ex_advance) && mem_ready;
    wire branch_redirect = ex_advance && !ex_fault && actual_next != x.pred;
    wire fault_transfer = ex_advance && ex_fault;
    wire id_special = dec_csr || dec_atomic || dec_fence || dec_mret ||
        dec_sret || dec_wfi || dec_sfence;
    wire serial_active = (id_v && id_special) || (x_v && x_serial) ||
        (m_v && m.special) || (w_v && w.special);
    wire id_advance = rst_n && running && id_v && ex_ready && !interlock &&
        !older_fault && !branch_redirect && !fault_transfer &&
        !(x_v && x_serial) && !(m_v && m.special) && !(w_v && w.special) &&
        (!id_special || (!x_v && !m_v && !w_v));
    wire serial_commit = wb_commit && w.special;
    wire fetch_request = rst_n && running && !fetch_busy && queue_count < 4 && !stopping &&
        !halt_req && !sleeping && !irq_stop && !serial_active &&
        !older_fault && !branch_redirect && !fault_transfer && !serial_commit;
    wire fetch_discard = fetch_kill || stopping || halt_req || irq_stop ||
        serial_active || older_fault || branch_redirect || fault_transfer || serial_commit;
    wire fetch_response = fetch_busy && i_rsp_valid && i_rsp_ready;
    wire queue_push = fetch_response && !fetch_discard;
    wire queue_pop = rst_n && running && queue_count != 0 &&
        (queue_release || stopping || halt_req || irq_stop) &&
        (!id_v || id_advance) && !serial_active && !older_fault &&
        !branch_redirect && !fault_transfer && !serial_commit;
    wire queue_flush = trap_enter || serial_commit || branch_redirect ||
        fault_transfer || mem_fault_now;
    assign queue_head_bits = fetch_queue[queue_read];
    always @* queue_head = queue_head_bits;
    wire [63:0] predicted_next;
    hammer_v2_predictor #(.PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES))
    u_predictor (
        .clk(clk), .rst_n(rst_n), .pc(fetch_context), .insn(i_rsp_rdata[31:0]),
        .next_pc(predicted_next),
        .update(ex_advance && !ex_fault && (x.branch || x.jump)),
        .update_pc(x.pc), .update_target(control_target),
        .update_taken(control_taken), .update_conditional(x.branch)
    );
    hammer_v2_muldiv u_muldiv (
        .clk(clk), .rst_n(rst_n), .start(md_start), .op(x.m_op),
        .word_op(x.word_op), .a(forward_a), .b(forward_b),
        .busy(md_busy), .done(md_done), .result(md_result),
        .consume(ex_advance && x.muldiv || trap_enter)
    );
    assign halted = !rst_n || !running;
    assign i_req_valid = fetch_request || fence_i_request;
    assign i_req_cmd = fence_i_request ? 2'b11 : 2'b0;
    assign i_req_addr = fetch_request ? fetch_pc : 64'b0;
    assign i_rsp_ready = rst_n && ((fetch_busy &&
        (fetch_discard || queue_count < 4)) ||
        (running && m_v && m.fence_i && m.phase == 3));
    assign d_req_valid = halt_d_request || fence_d_request ||
        (rst_n && running && m_v && m.atomic && atom_req_valid) || normal_d_request;
    assign d_req_cmd = halt_d_request || fence_d_request ? 2'b10 :
        m_v && m.atomic ? atom_req_cmd :
        normal_d_request && m.store ? 2'b01 : 2'b0;
    assign d_req_addr = d_req_valid && m_v && m.atomic ? atom_req_addr :
        normal_d_request ? m.addr : 64'b0;
    assign d_req_wdata = d_req_valid && m_v && m.atomic ? atom_req_wdata :
        normal_d_request && m.store ? m.wdata : 64'b0;
    assign d_req_wstrb = d_req_valid && m_v && m.atomic ? atom_req_wstrb :
        normal_d_request && m.store ? m.mask : 8'b0;
    assign d_rsp_ready = rst_n && ((halt_clean && halt_phase == 2) ||
        (running && m_v && m.fence && m.phase == 1) ||
        (running && m_v && m.atomic && atom_rsp_ready) ||
        (running && m_v && !m.atomic && !m.mmio && !m.clint &&
         (m.load || m.store) && m.sent && !trap_enter));
    assign a_valid = mem_request && m.mmio;
    assign a_write = a_valid && m.store;
    assign a_addr = a_valid ? {m.addr[31:3],3'b0} : 32'b0;
    assign a_wdata = a_write ? m.wdata : 64'b0;
    assign a_wstrb = a_write ? m.mask : 8'b0;
    assign a_rsp_ready = rst_n && running && m_v && m.mmio && m.sent &&
        !trap_enter;
    assign c_req_valid = mem_request && m.clint;
    assign c_req_write = c_req_valid && m.store;
    assign c_req_size = c_req_valid ? m.size[1:0] : 2'b0;
    assign c_req_addr = c_req_valid ? m.addr : 64'b0;
    assign c_req_wdata = c_req_write ? m.wdata : 64'b0;
    assign c_req_wstrb = c_req_write ? m.mask : 8'b0;
    assign c_rsp_ready = rst_n && running && m_v && m.clint && m.sent &&
        !trap_enter;
    assign stall_load_use = rst_n && running && id_v && interlock &&
        !older_fault && !branch_redirect;
    assign stall_mem = rst_n && running && m_v && !mem_advance && !trap_enter;
    assign stall_muldiv = rst_n && running && x_v && x.muldiv &&
        !ex_complete && !older_fault;
    assign redirect_valid = rst_n && redirect_event;
    assign redirect_pc = redirect_valid ? redirect_event_pc : 64'b0;
    assign ex_valid = rst_n && running && x_v && !older_fault;
    assign ex_pc = ex_valid ? x.pc : 64'b0;
    assign ex_rs1_sel = ex_valid && !x.fault ? sel1 : 2'b0;
    assign ex_rs2_sel = ex_valid && !x.fault ? sel2 : 2'b0;
    assign ex_store_sel = ex_valid && x.store && !x.fault ? store_sel : 2'b0;

    integer queue_slot;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            queue_read <= 2'b0;
            queue_write <= 2'b0;
            queue_count <= 3'b0;
            queue_release <= 1'b0;
            for (queue_slot = 0; queue_slot < 4; queue_slot = queue_slot + 1)
                fetch_queue[queue_slot] <= '0;
        end else if (!running || queue_flush) begin
            queue_read <= 2'b0;
            queue_write <= 2'b0;
            queue_count <= 3'b0;
            queue_release <= 1'b0;
        end else begin
            case ({queue_push,queue_pop})
                2'b10: queue_count <= queue_count + 3'd1;
                2'b01: queue_count <= queue_count - 3'd1;
                default: begin end
            endcase
            if (queue_count == 4) queue_release <= 1'b1;
            if (queue_count == 1 && queue_pop && !queue_push)
                queue_release <= 1'b0;
            if (queue_push) begin
                fetch_queue[queue_write] <=
                    {fetch_context,predicted_next,i_rsp_rdata[31:0],i_rsp_error};
                queue_write <= queue_write + 2'd1;
            end
            if (queue_pop) queue_read <= queue_read + 2'd1;
        end
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            running <= 1'b0;
            stopping <= 1'b0;
            sleeping <= 1'b0;
            legacy_stop <= 1'b0;
            halt_phase <= 2'b0;
            fetch_pc <= 64'b0;
            committed_next <= 64'b0;
            fetch_context <= 64'b0;
            fetch_busy <= 1'b0;
            fetch_kill <= 1'b0;
            id_v <= 1'b0;
            id_error <= 1'b0;
            id_pc <= 64'b0;
            id_pred <= 64'b0;
            id_insn <= 32'b0;
            x_v <= 1'b0;
            m_v <= 1'b0;
            w_v <= 1'b0;
            x <= '0;
            m <= '0;
            w <= '0;
            redirect_event <= 1'b0;
            redirect_event_pc <= 64'b0;
            trap_valid <= 1'b0;
            trap_pc <= 64'b0;
            trap_cause <= 64'b0;
            trap_tval <= 64'b0;
            trap_target_priv <= 2'b0;
            trap_interrupt <= 1'b0;
            retire_valid <= 1'b0;
            retire_pc <= 64'b0;
            retire_next_pc <= 64'b0;
            retire_insn <= 32'b0;
            retire_priv <= 2'b0;
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
            redirect_event <= trap_enter || serial_commit || branch_redirect;
            redirect_event_pc <= trap_enter ? entry_vector :
                serial_commit ? wb_next : branch_redirect ? actual_next : 64'b0;
            retire_valid <= 1'b0;
            retire_pc <= 64'b0;
            retire_next_pc <= 64'b0;
            retire_insn <= 32'b0;
            retire_priv <= 2'b0;
            retire_rd_we <= 1'b0;
            retire_rd <= 5'b0;
            retire_rd_data <= 64'b0;
            retire_mem_valid <= 1'b0;
            retire_mem_write <= 1'b0;
            retire_mem_addr <= 64'b0;
            retire_mem_wmask <= 8'b0;
            retire_mem_wdata <= 64'b0;
            retire_mem_rdata <= 64'b0;
            if (!LEGACY_TRAPS) begin
                trap_valid <= 1'b0;
                trap_pc <= 64'b0;
                trap_cause <= 64'b0;
                trap_tval <= 64'b0;
                trap_target_priv <= 2'b0;
                trap_interrupt <= 1'b0;
            end
            if (wb_commit) begin
                retire_valid <= 1'b1;
                retire_pc <= w.pc;
                retire_next_pc <= wb_next;
                retire_insn <= w.insn;
                retire_priv <= w.priv;
                retire_rd_we <= wb_we;
                if (wb_we) begin
                    retire_rd <= w.rd;
                    retire_rd_data <= wb_data;
                end
                retire_mem_valid <= w.mem_valid;
                if (w.mem_valid) begin
                    retire_mem_addr <= w.addr;
                    retire_mem_write <= w.mem_write;
                    retire_mem_wmask <= w.mask;
                    retire_mem_wdata <= w.wdata;
                    retire_mem_rdata <= w.rdata;
                end
                committed_next <= wb_next;
            end
            if (fetch_request && i_req_ready) begin
                fetch_busy <= 1'b1;
                fetch_kill <= 1'b0;
                fetch_context <= fetch_pc;
            end
            if (fetch_response) begin
                fetch_busy <= 1'b0;
                fetch_kill <= 1'b0;
                if (!fetch_discard) fetch_pc <= predicted_next;
            end
            if (queue_pop) begin
                id_v <= 1'b1;
                id_pc <= queue_head.pc;
                id_pred <= queue_head.pred;
                id_insn <= queue_head.insn;
                id_error <= queue_head.error;
            end
            if (running) begin
                w_v <= 1'b0;
                if (halt_req) stopping <= 1'b1;
                if (sleeping && trap_wake) sleeping <= 1'b0;
                if (halt_clean) begin
                    if (halt_d_request && d_req_ready) halt_phase <= 2'd2;
                    if (halt_complete) begin
                        running <= 1'b0;
                        stopping <= 1'b0;
                        sleeping <= 1'b0;
                        halt_phase <= 2'b0;
                        fetch_pc <= committed_next;
                    end
                end
                if (a_valid && a_ready || c_req_valid && c_req_ready ||
                    normal_d_request && d_req_ready) m.sent <= 1'b1;
                if (atom_start) m.atom_started <= 1'b1;
                if (fence_d_request && d_req_ready) m.phase <= 2'd1;
                if (fence_d_done && !d_rsp_error && m.fence_i) m.phase <= 2'd2;
                if (fence_i_request && i_req_ready) m.phase <= 2'd3;
                if (mem_advance) begin
                    m_v <= 1'b0;
                    w_v <= 1'b1;
                    w <= '0;
                    w.pc <= m.pc;
                    w.next_pc <= m.next_pc;
                    w.insn <= m.insn;
                    w.priv <= m.priv;
                    w.rd <= m.rd;
                    w.we <= m.we && !mem_fault_now;
                    w.fault <= mem_fault_now;
                    w.cause <= mem_cause_now;
                    w.tval <= mem_tval_now;
                    w.addr <= m.addr;
                    w.src <= m.src;
                    w.csr <= m.csr;
                    w.mret <= m.mret;
                    w.sret <= m.sret;
                    w.wfi <= m.wfi;
                    w.special <= m.special;
                    w.result <= m.result;
                    if (!mem_fault_now) begin
                        if (m.load) begin
                            w.result <= extend_load(selected_rsp_data,m.addr[2:0],m.size);
                            w.rdata <= extend_load(selected_rsp_data,m.addr[2:0],m.size);
                            w.mem_valid <= 1'b1;
                        end
                        if (m.store) begin
                            w.mem_valid <= 1'b1;
                            w.mem_write <= 1'b1;
                            w.wdata <= m.wdata;
                            w.mask <= m.mask;
                        end
                        if (m.atomic) begin
                            w.result <= atom_result;
                            w.rdata <= atom_old;
                            w.mem_valid <= 1'b1;
                            w.mem_write <= atom_write;
                            w.wdata <= atom_wdata;
                            w.mask <= atom_mask;
                        end
                    end
                end
                if (ex_advance) begin
                    x_v <= 1'b0;
                    m_v <= 1'b1;
                    m <= '0;
                    m.pc <= x.pc;
                    m.next_pc <= actual_next;
                    m.insn <= x.insn;
                    m.priv <= x.priv;
                    m.rd <= x.rd;
                    m.we <= x.we;
                    m.fault <= ex_fault;
                    m.cause <= ex_cause;
                    m.tval <= ex_tval;
                    m.addr <= effective_addr;
                    m.src <= x.atomic ? forward_b : forward_a;
                    m.wdata <= forward_b << {effective_addr[2:0],3'b0};
                    m.mask <= base_mask << effective_addr[2:0];
                    m.size <= x.size;
                    m.load <= x.load;
                    m.store <= x.store;
                    m.mmio <= (x.load || x.store) && addr_mmio;
                    m.clint <= (x.load || x.store) && addr_clint;
                    m.csr <= x.csr;
                    m.atomic <= x.atomic;
                    m.fence <= x.fence;
                    m.fence_i <= x.fence_i;
                    m.mret <= x.mret;
                    m.sret <= x.sret;
                    m.wfi <= x.wfi;
                    m.sfence <= x.sfence;
                    m.special <= x_serial;
                    if (x.jump) m.result <= x.pc + 64'd4;
                    else if (x.muldiv) m.result <= md_result;
                    else m.result <= alu_result;
                end else if (x_v) begin
                    x.a <= forward_a;
                    x.b <= forward_b;
                end
                if (md_start) x.md_started <= 1'b1;
                if (id_advance) begin
                    id_v <= queue_pop;
                    x_v <= 1'b1;
                    x <= '0;
                    x.pc <= id_pc;
                    x.pred <= id_pred;
                    x.insn <= id_insn;
                    x.priv <= current_priv;
                    x.a <= rf_a;
                    x.b <= rf_b;
                    x.imm <= dec_imm;
                    x.rs1 <= dec_rs1;
                    x.rs2 <= dec_rs2;
                    x.rd <= dec_rd;
                    x.use1 <= dec_use1;
                    x.use2 <= dec_use2;
                    x.we <= dec_we;
                    x.a_pc <= dec_a_pc;
                    x.b_imm <= dec_b_imm;
                    x.word_op <= dec_word;
                    x.alu <= dec_alu;
                    x.load <= dec_load;
                    x.store <= dec_store;
                    x.branch <= dec_branch;
                    x.jump <= dec_jump;
                    x.jalr <= dec_jalr;
                    x.muldiv <= dec_muldiv;
                    x.size <= dec_size;
                    x.branch_op <= dec_branch_op;
                    x.m_op <= dec_m_op;
                    x.csr <= dec_csr;
                    x.atomic <= dec_atomic;
                    x.fence <= dec_fence;
                    x.fence_i <= dec_fence_i;
                    x.mret <= dec_mret;
                    x.sret <= dec_sret;
                    x.wfi <= dec_wfi;
                    x.sfence <= dec_sfence;
                    x.special <= id_special;
                    x.fault <= id_error || dec_illegal || dec_trap;
                    if (id_error) begin
                        x.cause <= |id_pc[1:0] ? 4'd0 : 4'd1;
                        x.tval <= id_pc;
                    end else if (dec_illegal) begin
                        x.cause <= 4'd2;
                        x.tval <= {32'b0,id_insn};
                    end else if (dec_trap) begin
                        if (dec_cause == 3) begin
                            x.cause <= 4'd3;
                            x.tval <= id_pc;
                        end else begin
                            if (current_priv == 0) x.cause <= 4'd8;
                            else if (current_priv == 1) x.cause <= 4'd9;
                            else x.cause <= 4'd11;
                            x.tval <= 64'b0;
                        end
                    end
                end
                if (branch_redirect) begin
                    id_v <= 1'b0;
                    fetch_pc <= actual_next;
                    if (fetch_busy && !fetch_response) fetch_kill <= 1'b1;
                end
                if (fault_transfer) begin
                    id_v <= 1'b0;
                    if (fetch_busy && !fetch_response) fetch_kill <= 1'b1;
                end
                if (mem_fault_now) begin
                    id_v <= 1'b0;
                    x_v <= 1'b0;
                    if (fetch_busy && !fetch_response) fetch_kill <= 1'b1;
                end
                if (serial_commit) begin
                    id_v <= 1'b0;
                    x_v <= 1'b0;
                    m_v <= 1'b0;
                    fetch_pc <= wb_next;
                    if (fetch_busy && !fetch_response) fetch_kill <= 1'b1;
                    if (w.wfi && !trap_wake) sleeping <= 1'b1;
                end
                if (trap_enter) begin
                    trap_valid <= 1'b1;
                    trap_pc <= entry_epc;
                    trap_cause <= entry_cause;
                    trap_tval <= entry_tval;
                    trap_target_priv <= trap_destination;
                    trap_interrupt <= trap_is_interrupt;
                    committed_next <= entry_vector;
                    fetch_pc <= entry_vector;
                    id_v <= 1'b0;
                    x_v <= 1'b0;
                    m_v <= 1'b0;
                    w_v <= 1'b0;
                    sleeping <= 1'b0;
                    halt_phase <= 2'b0;
                    if (halt_clean_fault) stopping <= 1'b0;
                    if (fetch_busy && !fetch_response) fetch_kill <= 1'b1;
                    if (LEGACY_TRAPS) begin
                        stopping <= 1'b1;
                        legacy_stop <= 1'b1;
                    end
                end
            end else if (start && !halt_req && !legacy_stop) begin
                running <= 1'b1;
                stopping <= 1'b0;
                sleeping <= 1'b0;
                halt_phase <= 2'b0;
                fetch_pc <= committed_next;
                id_v <= 1'b0;
                x_v <= 1'b0;
                m_v <= 1'b0;
                w_v <= 1'b0;
            end
        end
    end
endmodule
