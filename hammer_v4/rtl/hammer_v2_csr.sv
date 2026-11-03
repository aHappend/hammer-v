module hammer_v2_csr (
    input wire clk, rst_n,
    input wire csr_valid, csr_commit,
    input wire [11:0] csr_addr,
    input wire [2:0] csr_op,
    input wire [63:0] csr_src,
    input wire csr_read, csr_write,
    output wire [63:0] csr_rdata,
    output wire csr_illegal,
    input wire retire,
    input wire [63:0] mtime,
    input wire irq_msip, irq_mtip, irq_meip, irq_seip,
    input wire [1:0] return_kind,
    input wire return_commit,
    output wire return_illegal,
    output wire [63:0] return_pc,
    input wire trap_enter,
    input wire [1:0] trap_target,
    input wire [63:0] trap_epc, trap_cause, trap_tval,
    output wire [1:0] priv,
    output wire [63:0] mstatus, mie, mip, medeleg, mideleg,
    output wire [63:0] mtvec, stvec, mepc, sepc
);
    localparam [63:0] STATUS_MASK = (64'd1 << 1) | (64'd1 << 3) |
        (64'd1 << 5) | (64'd1 << 7) | (64'd1 << 8) | (64'd3 << 11) |
        (64'd1 << 17) | (64'd1 << 20) | (64'd1 << 21) | (64'd1 << 22);
    localparam [63:0] SSTATUS_MASK = (64'd1 << 1) | (64'd1 << 5) |
        (64'd1 << 8);
    localparam [63:0] XLEN_FIELDS = (64'd2 << 32) | (64'd2 << 34);
    localparam [63:0] MISA = (64'd2 << 62) | (64'd1 << 0) |
        (64'd1 << 8) | (64'd1 << 12) | (64'd1 << 18) | (64'd1 << 20);
    reg [1:0] priv_q;
    reg [63:0] status_q, mie_q, medeleg_q, mideleg_q;
    reg [63:0] mtvec_q, stvec_q, mepc_q, sepc_q;
    reg [63:0] mscratch_q, sscratch_q, mcause_q, scause_q, mtval_q, stval_q;
    reg [63:0] mcycle_q, minstret_q;
    reg [2:0] mcounteren_q, scounteren_q;
    reg ssip_q, stip_q;
    reg [63:0] raw_read;
    reg exists, counter_denied;
    wire [63:0] pending = {52'b0,irq_meip,1'b0,irq_seip,1'b0,
        irq_mtip,1'b0,stip_q,1'b0,irq_msip,1'b0,ssip_q,1'b0};
    wire [63:0] supervisor_mask = mideleg_q & 64'h222;
    wire op_valid = csr_op == 1 || csr_op == 2 || csr_op == 3 ||
        csr_op == 5 || csr_op == 6 || csr_op == 7;
    wire privilege_denied = priv_q < csr_addr[9:8];
    wire readonly_denied = csr_write && csr_addr[11:10] == 2'b11;
    wire tvm_denied = csr_addr == 12'h180 && priv_q == 1 && status_q[20];
    wire illegal_query = !exists || !op_valid || privilege_denied ||
        readonly_denied || counter_denied || tvm_denied;
    wire write_enable = rst_n && csr_valid && csr_commit && csr_write &&
        !illegal_query && !trap_enter && !return_commit;
    wire [63:0] changed = csr_op[1:0] == 1 ? csr_src :
        csr_op[1:0] == 2 ? raw_read | csr_src : raw_read & ~csr_src;
    wire [63:0] changed_status = changed & STATUS_MASK;
    wire [1:0] changed_mpp = changed[12:11] == 2 ? 2'b0 : changed[12:11];
    wire bad_return = return_kind == 1 ? priv_q != 3 :
        return_kind == 2 ? (priv_q == 0 || (priv_q == 1 && status_q[22])) :
        return_kind != 0;
    assign priv = rst_n ? priv_q : 2'b0;
    assign mstatus = rst_n ? status_q | XLEN_FIELDS : 64'b0;
    assign mie = rst_n ? mie_q : 64'b0;
    assign mip = rst_n ? pending : 64'b0;
    assign medeleg = rst_n ? medeleg_q : 64'b0;
    assign mideleg = rst_n ? mideleg_q : 64'b0;
    assign mtvec = rst_n ? mtvec_q : 64'b0;
    assign stvec = rst_n ? stvec_q : 64'b0;
    assign mepc = rst_n ? mepc_q : 64'b0;
    assign sepc = rst_n ? sepc_q : 64'b0;
    assign csr_illegal = rst_n && csr_valid && illegal_query;
    assign csr_rdata = rst_n && csr_valid && csr_read && !illegal_query ?
        raw_read : 64'b0;
    assign return_illegal = rst_n && return_kind != 0 && bad_return;
    assign return_pc = rst_n && return_kind != 0 && !bad_return ?
        (return_kind == 1 ? mepc_q : sepc_q) : 64'b0;
    always @* begin
        exists = 1'b1;
        counter_denied = 1'b0;
        raw_read = 64'b0;
        case (csr_addr)
            12'h100: raw_read = (status_q & SSTATUS_MASK) | (64'd2 << 32);
            12'h104: raw_read = mie_q & supervisor_mask;
            12'h105: raw_read = stvec_q;
            12'h106: raw_read = {61'b0,scounteren_q};
            12'h140: raw_read = sscratch_q;
            12'h141: raw_read = sepc_q;
            12'h142: raw_read = scause_q;
            12'h143: raw_read = stval_q;
            12'h144: raw_read = pending & supervisor_mask;
            12'h180: raw_read = 64'b0;
            12'h300: raw_read = status_q | XLEN_FIELDS;
            12'h301: raw_read = MISA;
            12'h302: raw_read = medeleg_q;
            12'h303: raw_read = mideleg_q;
            12'h304: raw_read = mie_q;
            12'h305: raw_read = mtvec_q;
            12'h306: raw_read = {61'b0,mcounteren_q};
            12'h340: raw_read = mscratch_q;
            12'h341: raw_read = mepc_q;
            12'h342: raw_read = mcause_q;
            12'h343: raw_read = mtval_q;
            12'h344: raw_read = pending;
            12'hb00,12'hc00: raw_read = mcycle_q;
            12'hc01: raw_read = mtime;
            12'hb02,12'hc02: raw_read = minstret_q;
            12'hf11,12'hf12,12'hf13,12'hf14: raw_read = 64'b0;
            default: exists = 1'b0;
        endcase
        case (csr_addr)
            12'hc00: counter_denied = priv_q != 3 &&
                (!mcounteren_q[0] || (priv_q == 0 && !scounteren_q[0]));
            12'hc01: counter_denied = priv_q != 3 &&
                (!mcounteren_q[1] || (priv_q == 0 && !scounteren_q[1]));
            12'hc02: counter_denied = priv_q != 3 &&
                (!mcounteren_q[2] || (priv_q == 0 && !scounteren_q[2]));
            default: begin end
        endcase
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            priv_q <= 2'd3;
            status_q <= 64'b0;
            mie_q <= 64'b0;
            medeleg_q <= 64'b0;
            mideleg_q <= 64'b0;
            mtvec_q <= 64'b0;
            stvec_q <= 64'b0;
            mepc_q <= 64'b0;
            sepc_q <= 64'b0;
            mscratch_q <= 64'b0;
            sscratch_q <= 64'b0;
            mcause_q <= 64'b0;
            scause_q <= 64'b0;
            mtval_q <= 64'b0;
            stval_q <= 64'b0;
            mcycle_q <= 64'b0;
            minstret_q <= 64'b0;
            mcounteren_q <= 3'b0;
            scounteren_q <= 3'b0;
            ssip_q <= 1'b0;
            stip_q <= 1'b0;
        end else begin
            mcycle_q <= mcycle_q + 64'd1;
            if (retire) minstret_q <= minstret_q + 64'd1;
            if (write_enable) begin
                case (csr_addr)
                    12'h100: status_q <= (status_q & ~SSTATUS_MASK) |
                        (changed & SSTATUS_MASK);
                    12'h104: mie_q <= (mie_q & ~supervisor_mask) |
                        (changed & supervisor_mask);
                    12'h105: stvec_q <= {changed[63:2],1'b0,
                        changed[1:0] == 2'b01};
                    12'h106: scounteren_q <= changed[2:0];
                    12'h140: sscratch_q <= changed;
                    12'h141: sepc_q <= {changed[63:2],2'b0};
                    12'h142: scause_q <= changed;
                    12'h143: stval_q <= changed;
                    12'h144: if (supervisor_mask[1]) ssip_q <= changed[1];
                    12'h300: status_q <= (changed_status & ~(64'd3 << 11)) |
                        ({62'b0,changed_mpp} << 11);
                    12'h302: medeleg_q <= changed & 64'h3ff;
                    12'h303: mideleg_q <= changed & 64'h222;
                    12'h304: mie_q <= changed & 64'haaa;
                    12'h305: mtvec_q <= {changed[63:2],1'b0,
                        changed[1:0] == 2'b01};
                    12'h306: mcounteren_q <= changed[2:0];
                    12'h340: mscratch_q <= changed;
                    12'h341: mepc_q <= {changed[63:2],2'b0};
                    12'h342: mcause_q <= changed;
                    12'h343: mtval_q <= changed;
                    12'h344: begin
                        ssip_q <= changed[1];
                        stip_q <= changed[5];
                    end
                    12'hb00: mcycle_q <= changed;
                    12'hb02: minstret_q <= changed;
                    default: begin end
                endcase
            end
            if (return_commit && return_kind != 0 && !bad_return &&
                !trap_enter) begin
                if (return_kind == 1) begin
                    priv_q <= status_q[12:11];
                    status_q[3] <= status_q[7];
                    status_q[7] <= 1'b1;
                    status_q[12:11] <= 2'b0;
                    if (status_q[12:11] != 3) status_q[17] <= 1'b0;
                end else begin
                    priv_q <= {1'b0,status_q[8]};
                    status_q[1] <= status_q[5];
                    status_q[5] <= 1'b1;
                    status_q[8] <= 1'b0;
                    status_q[17] <= 1'b0;
                end
            end
            if (trap_enter) begin
                priv_q <= trap_target;
                if (trap_target == 1) begin
                    sepc_q <= {trap_epc[63:2],2'b0};
                    scause_q <= trap_cause;
                    stval_q <= trap_tval;
                    status_q[5] <= status_q[1];
                    status_q[1] <= 1'b0;
                    status_q[8] <= priv_q == 1;
                end else begin
                    mepc_q <= {trap_epc[63:2],2'b0};
                    mcause_q <= trap_cause;
                    mtval_q <= trap_tval;
                    status_q[7] <= status_q[3];
                    status_q[3] <= 1'b0;
                    status_q[12:11] <= priv_q;
                end
            end
        end
    end
endmodule
