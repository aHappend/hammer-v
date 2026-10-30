module hammer_v3_top #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16,
    parameter integer ICACHE_LINES = 64,
    parameter integer DCACHE_LINES = 64,
    parameter integer LEGACY_TRAPS = 0,
    parameter integer ITLB_ENTRIES = 8,
    parameter integer DTLB_ENTRIES = 8
) (
    input wire clk, rst_n, start,
    input wire host_valid, host_write, host_imem,
    input wire [31:0] host_addr,
    input wire [63:0] host_wdata,
    input wire [7:0] host_wstrb,
    input wire [4:0] dbg_raddr,
    output wire halted, host_ready,
    output reg host_rsp_valid, host_rsp_error,
    output reg [63:0] host_rdata,
    output wire [63:0] dbg_rdata,
    output wire trap_valid,
    output wire [63:0] trap_pc, trap_cause,
    output wire retire_valid,
    output wire [63:0] retire_pc, retire_next_pc,
    output wire [31:0] retire_insn,
    output wire retire_rd_we,
    output wire [4:0] retire_rd,
    output wire [63:0] retire_rd_data,
    output wire retire_mem_valid, retire_mem_write,
    output wire [63:0] retire_mem_addr,
    output wire [7:0] retire_mem_wmask,
    output wire [63:0] retire_mem_wdata, retire_mem_rdata,
    output wire stall_load_use, stall_mem, stall_muldiv,
    output wire redirect_valid,
    output wire [63:0] redirect_pc,
    output wire ex_valid,
    output wire [63:0] ex_pc,
    output wire [1:0] ex_rs1_sel, ex_rs2_sel, ex_store_sel,
    output wire [31:0] m_axi_awaddr,
    output wire [2:0] m_axi_awprot,
    output wire m_axi_awvalid,
    output wire [63:0] m_axi_wdata,
    output wire [7:0] m_axi_wstrb,
    output wire m_axi_wvalid, m_axi_bready,
    output wire [31:0] m_axi_araddr,
    output wire [2:0] m_axi_arprot,
    output wire m_axi_arvalid, m_axi_rready,
    input wire m_axi_awready, m_axi_wready,
    input wire [1:0] m_axi_bresp,
    input wire m_axi_bvalid, m_axi_arready,
    input wire [63:0] m_axi_rdata,
    input wire [1:0] m_axi_rresp,
    input wire m_axi_rvalid,
    input wire halt_req, irq_meip, irq_seip,
    output wire [1:0] retire_priv,
    output wire [63:0] trap_tval,
    output wire [1:0] trap_target_priv,
    output wire trap_interrupt,
    input wire uart_rx,
    output wire uart_tx,
    input wire [30:0] plic_sources,
    output wire [3:0] m_mem_axi_awid,
    output wire [63:0] m_mem_axi_awaddr,
    output wire [7:0] m_mem_axi_awlen,
    output wire [2:0] m_mem_axi_awsize,
    output wire [1:0] m_mem_axi_awburst,
    output wire m_mem_axi_awlock,
    output wire [3:0] m_mem_axi_awcache,
    output wire [2:0] m_mem_axi_awprot,
    output wire [3:0] m_mem_axi_awqos,
    output wire m_mem_axi_awvalid,
    input wire m_mem_axi_awready,
    output wire [63:0] m_mem_axi_wdata,
    output wire [7:0] m_mem_axi_wstrb,
    output wire m_mem_axi_wlast, m_mem_axi_wvalid,
    input wire m_mem_axi_wready,
    input wire [3:0] m_mem_axi_bid,
    input wire [1:0] m_mem_axi_bresp,
    input wire m_mem_axi_bvalid,
    output wire m_mem_axi_bready,
    output wire [3:0] m_mem_axi_arid,
    output wire [63:0] m_mem_axi_araddr,
    output wire [7:0] m_mem_axi_arlen,
    output wire [2:0] m_mem_axi_arsize,
    output wire [1:0] m_mem_axi_arburst,
    output wire m_mem_axi_arlock,
    output wire [3:0] m_mem_axi_arcache,
    output wire [2:0] m_mem_axi_arprot,
    output wire [3:0] m_mem_axi_arqos,
    output wire m_mem_axi_arvalid,
    input wire m_mem_axi_arready,
    input wire [3:0] m_mem_axi_rid,
    input wire [63:0] m_mem_axi_rdata,
    input wire [1:0] m_mem_axi_rresp,
    input wire m_mem_axi_rlast, m_mem_axi_rvalid,
    output wire m_mem_axi_rready,
    input wire [3:0] s_acc_axi_awid,
    input wire [63:0] s_acc_axi_awaddr,
    input wire [7:0] s_acc_axi_awlen,
    input wire [2:0] s_acc_axi_awsize,
    input wire [1:0] s_acc_axi_awburst,
    input wire s_acc_axi_awlock,
    input wire [3:0] s_acc_axi_awcache,
    input wire [2:0] s_acc_axi_awprot,
    input wire [3:0] s_acc_axi_awqos,
    input wire s_acc_axi_awvalid,
    output wire s_acc_axi_awready,
    input wire [63:0] s_acc_axi_wdata,
    input wire [7:0] s_acc_axi_wstrb,
    input wire s_acc_axi_wlast, s_acc_axi_wvalid,
    output wire s_acc_axi_wready,
    output wire [3:0] s_acc_axi_bid,
    output wire [1:0] s_acc_axi_bresp,
    output wire s_acc_axi_bvalid,
    input wire s_acc_axi_bready,
    input wire [3:0] s_acc_axi_arid,
    input wire [63:0] s_acc_axi_araddr,
    input wire [7:0] s_acc_axi_arlen,
    input wire [2:0] s_acc_axi_arsize,
    input wire [1:0] s_acc_axi_arburst,
    input wire s_acc_axi_arlock,
    input wire [3:0] s_acc_axi_arcache,
    input wire [2:0] s_acc_axi_arprot,
    input wire [3:0] s_acc_axi_arqos,
    input wire s_acc_axi_arvalid,
    output wire s_acc_axi_arready,
    output wire [3:0] s_acc_axi_rid,
    output wire [63:0] s_acc_axi_rdata,
    output wire [1:0] s_acc_axi_rresp,
    output wire s_acc_axi_rlast, s_acc_axi_rvalid,
    input wire s_acc_axi_rready
);
    localparam integer LEGAL =
        IMEM_WORDS >= 1 && IMEM_WORDS <= 16384 &&
        DMEM_WORDS >= 1 && DMEM_WORDS <= 8192 &&
        (PRED_MODE == 0 || PRED_MODE == 1) &&
        (BTB_ENTRIES == 1 || BTB_ENTRIES == 4 || BTB_ENTRIES == 16 || BTB_ENTRIES == 64) &&
        (ICACHE_LINES == 1 || ICACHE_LINES == 4 || ICACHE_LINES == 16 || ICACHE_LINES == 64) &&
        (DCACHE_LINES == 1 || DCACHE_LINES == 4 || DCACHE_LINES == 16 || DCACHE_LINES == 64) &&
        (LEGACY_TRAPS == 0 || LEGACY_TRAPS == 1) &&
        (ITLB_ENTRIES == 1 || ITLB_ENTRIES == 4 || ITLB_ENTRIES == 8 || ITLB_ENTRIES == 16) &&
        (DTLB_ENTRIES == 1 || DTLB_ENTRIES == 4 || DTLB_ENTRIES == 8 || DTLB_ENTRIES == 16);
    initial if (!LEGAL)
        $fatal(1, "PARAMETER ERROR: illegal HAMMER-V3 configuration");
    generate if (LEGAL) begin : g_legal
        wire core_halted, core_start;
        wire exclusive, quiesce_valid, quiesce_ready, quiesce_error;
        reg launch_pending, resume_pending, progress_token;
        reg host_pending, host_wait, host_error_q, host_imem_q;
        reg host_dirty, maintenance_fault;
        reg [63:0] host_read_q;
        localparam [2:0] MIDLE=0, MDREQ=1, MDWAIT=2, MIREQ=3, MIWAIT=4, MDONE=5;
        reg [2:0] maintenance_state;
        reg maintenance_accel, maintenance_error;
        wire host_accept = host_valid && host_ready;
        wire host_bad = maintenance_fault ||
            (host_imem ? (|host_addr[1:0] ||
                {32'b0,host_addr} >= IMEM_WORDS*64'd4 ||
                |host_wdata[63:32] || |host_wstrb[7:4]) :
                (|host_addr[2:0] || {32'b0,host_addr} >= DMEM_WORDS*64'd8));
        wire h_imem = host_accept && host_imem && !host_bad;
        wire h_dmem = host_accept && !host_imem && !host_bad;
        wire [63:0] h_imem_data, h_dmem_data;
        wire maintenance_idle = maintenance_state == MIDLE && !host_dirty;
        assign halted = !rst_n ||
            (core_halted && !launch_pending && !resume_pending && !exclusive);
        assign host_ready = rst_n && halted && maintenance_idle &&
            !host_pending && !host_wait && !host_rsp_valid;
        wire start_accept = rst_n && start && halted &&
            !(LEGACY_TRAPS && trap_valid) && !host_valid &&
            !host_pending && !host_wait && !host_rsp_valid && !halt_req;
        assign core_start = rst_n && core_halted && !halt_req && !exclusive &&
            maintenance_idle && !maintenance_fault && !host_valid &&
            !host_pending && !host_wait && !host_rsp_valid &&
            (start_accept || launch_pending || resume_pending);
        wire allow_accel = rst_n && !host_valid && !host_pending && !host_wait &&
            !host_rsp_valid && maintenance_idle && !launch_pending && !start &&
            (core_halted ? !resume_pending : progress_token);
        wire accel_accept = (s_acc_axi_awvalid && s_acc_axi_awready) ||
            (s_acc_axi_arvalid && s_acc_axi_arready);

        wire ci_valid, ci_ready, ci_rsp_valid, ci_rsp_ready, ci_error, ci_page;
        wire [1:0] ci_cmd;
        wire [63:0] ci_addr, ci_data;
        wire cd_valid, cd_ready, cd_rsp_valid, cd_rsp_ready, cd_error, cd_page, cd_physical;
        wire [1:0] cd_cmd, cd_size, cd_access;
        wire [63:0] cd_addr, cd_wdata, cd_data;
        wire [7:0] cd_mask;
        wire [63:0] satp, status, mtime;
        wire [1:0] priv;
        wire sfence_valid, sfence_ready, sfence_va_valid, sfence_asid_valid;
        wire [63:0] sfence_va;
        wire [15:0] sfence_asid;
        wire at_valid, at_ready, at_rsp_valid, at_rsp_ready, at_error, at_page;
        wire [63:0] at_va;
        wire [1:0] at_access;
        wire [55:0] at_pa;
        wire msip, mtip, plic_meip, plic_seip, uart_irq;
        hammer_v3_core #(
            .IMEM_WORDS(IMEM_WORDS), .DMEM_WORDS(DMEM_WORDS),
            .PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES), .LEGACY_TRAPS(LEGACY_TRAPS)
        ) u_core (
            .clk(clk), .rst_n(rst_n), .start(core_start), .halt_req(halt_req || exclusive),
            .host_data_write((h_dmem && host_write) || quiesce_ready),
            .halted(core_halted), .irq_msip(msip), .irq_mtip(mtip),
            .irq_meip(irq_meip || plic_meip), .irq_seip(irq_seip || plic_seip),
            .mtime(mtime), .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata),
            .trap_valid(trap_valid), .trap_pc(trap_pc), .trap_cause(trap_cause),
            .trap_tval(trap_tval), .trap_target_priv(trap_target_priv),
            .trap_interrupt(trap_interrupt), .retire_valid(retire_valid),
            .retire_pc(retire_pc), .retire_next_pc(retire_next_pc),
            .retire_insn(retire_insn), .retire_priv(retire_priv),
            .retire_rd_we(retire_rd_we), .retire_rd(retire_rd), .retire_rd_data(retire_rd_data),
            .retire_mem_valid(retire_mem_valid), .retire_mem_write(retire_mem_write),
            .retire_mem_addr(retire_mem_addr), .retire_mem_wmask(retire_mem_wmask),
            .retire_mem_wdata(retire_mem_wdata), .retire_mem_rdata(retire_mem_rdata),
            .stall_load_use(stall_load_use), .stall_mem(stall_mem), .stall_muldiv(stall_muldiv),
            .redirect_valid(redirect_valid), .redirect_pc(redirect_pc),
            .ex_valid(ex_valid), .ex_pc(ex_pc), .ex_rs1_sel(ex_rs1_sel),
            .ex_rs2_sel(ex_rs2_sel), .ex_store_sel(ex_store_sel),
            .i_req_valid(ci_valid), .i_req_ready(ci_ready), .i_req_cmd(ci_cmd),
            .i_req_addr(ci_addr), .i_rsp_valid(ci_rsp_valid), .i_rsp_ready(ci_rsp_ready),
            .i_rsp_rdata(ci_data), .i_rsp_error(ci_error), .i_rsp_page_fault(ci_page),
            .d_req_valid(cd_valid), .d_req_ready(cd_ready), .d_req_cmd(cd_cmd),
            .d_req_addr(cd_addr), .d_req_wdata(cd_wdata), .d_req_wstrb(cd_mask),
            .d_req_size(cd_size), .d_req_access(cd_access), .d_req_physical(cd_physical),
            .d_rsp_valid(cd_rsp_valid), .d_rsp_ready(cd_rsp_ready),
            .d_rsp_rdata(cd_data), .d_rsp_error(cd_error), .d_rsp_page_fault(cd_page),
            .mmu_satp(satp), .mmu_priv(priv), .mmu_mstatus(status),
            .sfence_valid(sfence_valid), .sfence_ready(sfence_ready),
            .sfence_va_valid(sfence_va_valid), .sfence_asid_valid(sfence_asid_valid),
            .sfence_va(sfence_va), .sfence_asid(sfence_asid),
            .at_req_valid(at_valid), .at_req_ready(at_ready), .at_req_va(at_va),
            .at_req_access(at_access), .at_rsp_valid(at_rsp_valid), .at_rsp_ready(at_rsp_ready),
            .at_rsp_pa(at_pa), .at_rsp_error(at_error), .at_rsp_page_fault(at_page)
        );

        wire ti_valid, ti_ready, ti_rsp_valid, ti_rsp_ready, ti_page, ti_error;
        wire td_valid, td_ready, td_rsp_valid, td_rsp_ready, td_page, td_error;
        wire [63:0] ti_va, td_va;
        wire [55:0] ti_pa, td_pa;
        wire [1:0] td_access;
        wire pt_valid, pt_ready, pt_rsp_valid, pt_rsp_ready, pt_error;
        wire [55:0] pt_addr;
        wire [63:0] pt_data;
        hammer_v3_mmu #(.ITLB_ENTRIES(ITLB_ENTRIES), .DTLB_ENTRIES(DTLB_ENTRIES)) u_mmu (
            .clk(clk), .rst_n(rst_n), .satp(satp), .priv(priv), .mstatus(status),
            .i_req_valid(ti_valid), .i_req_ready(ti_ready), .i_req_va(ti_va), .i_req_bypass(1'b0),
            .i_rsp_valid(ti_rsp_valid), .i_rsp_ready(ti_rsp_ready), .i_rsp_pa(ti_pa),
            .i_rsp_page_fault(ti_page), .i_rsp_access_fault(ti_error),
            .d_req_valid(td_valid), .d_req_ready(td_ready), .d_req_va(td_va),
            .d_req_access(td_access), .d_req_bypass(1'b0),
            .d_rsp_valid(td_rsp_valid), .d_rsp_ready(td_rsp_ready), .d_rsp_pa(td_pa),
            .d_rsp_page_fault(td_page), .d_rsp_access_fault(td_error),
            .sfence_valid(sfence_valid), .sfence_ready(sfence_ready),
            .sfence_va_valid(sfence_va_valid), .sfence_asid_valid(sfence_asid_valid),
            .sfence_va(sfence_va), .sfence_asid(sfence_asid),
            .pt_req_valid(pt_valid), .pt_req_ready(pt_ready), .pt_req_addr(pt_addr),
            .pt_rsp_valid(pt_rsp_valid), .pt_rsp_ready(pt_rsp_ready),
            .pt_rsp_rdata(pt_data), .pt_rsp_error(pt_error)
        );
        wire pi_valid, pi_ready, pi_rsp_valid, pi_rsp_ready, pi_error;
        wire [63:0] pi_addr, pi_data;
        wire [1:0] pi_cmd;
        hammer_v3_fetch_path u_fetch_path (
            .clk(clk), .rst_n(rst_n), .req_valid(ci_valid), .req_ready(ci_ready),
            .req_addr(ci_addr), .req_cmd(ci_cmd), .rsp_valid(ci_rsp_valid),
            .rsp_ready(ci_rsp_ready), .rsp_rdata(ci_data), .rsp_error(ci_error), .rsp_page_fault(ci_page),
            .tr_valid(ti_valid), .tr_ready(ti_ready), .tr_va(ti_va),
            .tr_rsp_valid(ti_rsp_valid), .tr_rsp_ready(ti_rsp_ready), .tr_pa(ti_pa),
            .tr_page_fault(ti_page), .tr_access_fault(ti_error),
            .cache_valid(pi_valid), .cache_ready(pi_ready), .cache_addr(pi_addr),
            .cache_cmd(pi_cmd), .cache_rsp_valid(pi_rsp_valid), .cache_rsp_ready(pi_rsp_ready),
            .cache_rdata(pi_data), .cache_error(pi_error)
        );
        wire pd_valid, pd_ready, pd_rsp_valid, pd_rsp_ready, pd_error;
        wire [63:0] pd_addr, pd_wdata, pd_data;
        wire [7:0] pd_mask;
        wire [1:0] pd_cmd, pd_size;
        hammer_v3_data_path #(.DMEM_WORDS(DMEM_WORDS)) u_data_path (
            .clk(clk), .rst_n(rst_n), .req_valid(cd_valid), .req_ready(cd_ready),
            .req_physical(cd_physical), .req_addr(cd_addr), .req_wdata(cd_wdata), .req_wstrb(cd_mask),
            .req_cmd(cd_cmd), .req_size(cd_size), .req_access(cd_access),
            .rsp_valid(cd_rsp_valid), .rsp_ready(cd_rsp_ready), .rsp_rdata(cd_data),
            .rsp_error(cd_error), .rsp_page_fault(cd_page),
            .at_req_valid(at_valid), .at_req_ready(at_ready), .at_req_va(at_va),
            .at_req_access(at_access), .at_rsp_valid(at_rsp_valid), .at_rsp_ready(at_rsp_ready),
            .at_rsp_pa(at_pa), .at_rsp_error(at_error), .at_rsp_page_fault(at_page),
            .tr_valid(td_valid), .tr_ready(td_ready), .tr_va(td_va), .tr_access(td_access),
            .tr_rsp_valid(td_rsp_valid), .tr_rsp_ready(td_rsp_ready), .tr_pa(td_pa),
            .tr_page_fault(td_page), .tr_access_fault(td_error),
            .out_valid(pd_valid), .out_ready(pd_ready), .out_addr(pd_addr),
            .out_wdata(pd_wdata), .out_wstrb(pd_mask), .out_cmd(pd_cmd), .out_size(pd_size),
            .out_rsp_valid(pd_rsp_valid), .out_rsp_ready(pd_rsp_ready),
            .out_rdata(pd_data), .out_error(pd_error)
        );
        wire [4:0] route_valid, route_ready, route_rsp_valid, route_rsp_ready, route_error;
        wire [319:0] route_rdata;
        wire [63:0] route_addr, route_wdata;
        wire [7:0] route_mask;
        wire [1:0] route_cmd, route_size;
        wire route_write = route_cmd == 1;
        hammer_v3_data_router #(.DMEM_WORDS(DMEM_WORDS)) u_data_router (
            .clk(clk), .rst_n(rst_n), .req_valid(pd_valid), .req_ready(pd_ready),
            .req_addr(pd_addr), .req_wdata(pd_wdata), .req_wstrb(pd_mask),
            .req_cmd(pd_cmd), .req_size(pd_size), .rsp_valid(pd_rsp_valid),
            .rsp_ready(pd_rsp_ready), .rsp_rdata(pd_data), .rsp_error(pd_error),
            .target_valid(route_valid), .target_ready(route_ready),
            .target_addr(route_addr), .target_wdata(route_wdata), .target_wstrb(route_mask),
            .target_cmd(route_cmd), .target_size(route_size),
            .target_rsp_valid(route_rsp_valid), .target_rsp_ready(route_rsp_ready),
            .target_rsp_error(route_error), .target_rdata(route_rdata)
        );
        hammer_v2_clint u_clint (
            .clk(clk), .rst_n(rst_n), .req_valid(route_valid[1]), .req_ready(route_ready[1]),
            .req_write(route_write), .req_size(route_size), .req_addr(route_addr),
            .req_wdata(route_wdata), .req_wstrb(route_mask),
            .rsp_valid(route_rsp_valid[1]), .rsp_ready(route_rsp_ready[1]),
            .rsp_rdata(route_rdata[64 +: 64]), .rsp_error(route_error[1]),
            .mtime(mtime), .irq_msip(msip), .irq_mtip(mtip)
        );
        hammer_v3_plic u_plic (
            .clk(clk), .rst_n(rst_n), .uart_irq(uart_irq), .plic_sources(plic_sources),
            .irq_meip(plic_meip), .irq_seip(plic_seip),
            .req_valid(route_valid[2]), .req_ready(route_ready[2]),
            .req_write(route_write), .req_size(route_size), .req_addr(route_addr),
            .req_wdata(route_wdata), .req_wstrb(route_mask),
            .rsp_valid(route_rsp_valid[2]), .rsp_ready(route_rsp_ready[2]),
            .rsp_rdata(route_rdata[128 +: 64]), .rsp_error(route_error[2])
        );
        hammer_v3_uart u_uart (
            .clk(clk), .rst_n(rst_n), .uart_rx(uart_rx), .uart_tx(uart_tx), .irq(uart_irq),
            .req_valid(route_valid[3]), .req_ready(route_ready[3]),
            .req_write(route_write), .req_size(route_size), .req_addr(route_addr),
            .req_wdata(route_wdata), .req_wstrb(route_mask),
            .rsp_valid(route_rsp_valid[3]), .rsp_ready(route_rsp_ready[3]),
            .rsp_rdata(route_rdata[192 +: 64]), .rsp_error(route_error[3])
        );
        hammer_v2_axi_lite u_axi (
            .clk(clk), .rst_n(rst_n), .a_valid(route_valid[4]), .a_ready(route_ready[4]),
            .a_write(route_write), .a_addr({route_addr[31:3],3'b0}),
            .a_wdata(route_wdata), .a_wstrb(route_mask),
            .a_rsp_valid(route_rsp_valid[4]), .a_rsp_ready(route_rsp_ready[4]),
            .a_rdata(route_rdata[256 +: 64]), .a_error(route_error[4]),
            .m_axi_awaddr(m_axi_awaddr), .m_axi_awprot(m_axi_awprot),
            .m_axi_awvalid(m_axi_awvalid), .m_axi_wdata(m_axi_wdata),
            .m_axi_wstrb(m_axi_wstrb), .m_axi_wvalid(m_axi_wvalid),
            .m_axi_bready(m_axi_bready), .m_axi_araddr(m_axi_araddr),
            .m_axi_arprot(m_axi_arprot), .m_axi_arvalid(m_axi_arvalid),
            .m_axi_rready(m_axi_rready), .m_axi_awready(m_axi_awready),
            .m_axi_wready(m_axi_wready), .m_axi_bresp(m_axi_bresp),
            .m_axi_bvalid(m_axi_bvalid), .m_axi_arready(m_axi_arready),
            .m_axi_rdata(m_axi_rdata), .m_axi_rresp(m_axi_rresp), .m_axi_rvalid(m_axi_rvalid)
        );

        wire mi_request = rst_n && maintenance_state == MIREQ;
        wire md_request = rst_n && maintenance_state == MDREQ;
        wire [2:0] ia_ready, ia_rsp_valid, ia_rsp_ready, ia_error;
        wire [191:0] ia_data;
        wire [2:0] da_ready, da_rsp_valid, da_rsp_ready, da_error;
        wire [191:0] da_data;
        wire ic_valid, ic_ready, ic_rsp_valid, ic_rsp_ready, ic_error;
        wire dc_valid, dc_ready, dc_rsp_valid, dc_rsp_ready, dc_error;
        wire [1:0] ic_cmd, dc_cmd;
        wire [63:0] ic_addr, ic_wdata, ic_data, dc_addr, dc_wdata, dc_data;
        wire [7:0] ic_mask, dc_mask;
        assign pi_ready = ia_ready[0];
        assign pi_rsp_valid = ia_rsp_valid[0];
        assign pi_error = ia_error[0];
        assign pi_data = ia_data[63:0];
        assign ia_rsp_ready = {1'b0,maintenance_state == MIWAIT,pi_rsp_ready};
        hammer_v3_cache_arbiter u_i_arbiter (
            .clk(clk), .rst_n(rst_n), .req_valid({1'b0,mi_request,pi_valid}),
            .req_ready(ia_ready), .req_cmd({2'b0,2'b11,pi_cmd}),
            .req_addr({128'b0,pi_addr}), .req_wdata(192'b0), .req_wstrb(24'b0),
            .rsp_valid(ia_rsp_valid), .rsp_error(ia_error), .rsp_ready(ia_rsp_ready), .rsp_rdata(ia_data),
            .out_valid(ic_valid), .out_ready(ic_ready), .out_cmd(ic_cmd),
            .out_addr(ic_addr), .out_wdata(ic_wdata), .out_wstrb(ic_mask),
            .out_rsp_valid(ic_rsp_valid), .out_rsp_ready(ic_rsp_ready),
            .out_rsp_rdata(ic_data), .out_rsp_error(ic_error)
        );
        assign route_ready[0] = da_ready[0];
        assign route_rsp_valid[0] = da_rsp_valid[0];
        assign route_error[0] = da_error[0];
        assign route_rdata[63:0] = da_data[63:0];
        assign pt_ready = da_ready[1];
        assign pt_rsp_valid = da_rsp_valid[1];
        assign pt_error = da_error[1];
        assign pt_data = da_data[127:64];
        assign da_rsp_ready = {maintenance_state == MDWAIT,pt_rsp_ready,route_rsp_ready[0]};
        hammer_v3_cache_arbiter u_d_arbiter (
            .clk(clk), .rst_n(rst_n), .req_valid({md_request,pt_valid,route_valid[0]}),
            .req_ready(da_ready), .req_cmd({2'b11,2'b0,route_cmd}),
            .req_addr({64'b0,8'b0,pt_addr,route_addr}),
            .req_wdata({128'b0,route_wdata}), .req_wstrb({16'b0,route_mask}),
            .rsp_valid(da_rsp_valid), .rsp_error(da_error), .rsp_ready(da_rsp_ready), .rsp_rdata(da_data),
            .out_valid(dc_valid), .out_ready(dc_ready), .out_cmd(dc_cmd),
            .out_addr(dc_addr), .out_wdata(dc_wdata), .out_wstrb(dc_mask),
            .out_rsp_valid(dc_rsp_valid), .out_rsp_ready(dc_rsp_ready),
            .out_rsp_rdata(dc_data), .out_rsp_error(dc_error)
        );
        wire [2:0] back_valid, back_write, back_ready, back_rsp_valid, back_rsp_ready;
        wire [2:0] back_error, back_decerr;
        wire [191:0] back_addr, back_wdata, back_rdata;
        wire [23:0] back_mask;
        wire [1:0] effective_data_priv = priv == 3 && status[17] ? status[12:11] : priv;
        wire [8:0] back_prot = {3'b001,{2'b00,effective_data_priv != 0},
            {2'b10,priv != 0}};
        hammer_v3_icache #(.LINES(ICACHE_LINES), .WORDS(IMEM_WORDS)) u_icache (
            .clk(clk), .rst_n(rst_n), .req_valid(ic_valid), .req_ready(ic_ready),
            .req_cmd(ic_cmd), .req_addr(ic_addr), .req_wdata(ic_wdata), .req_wstrb(ic_mask),
            .rsp_valid(ic_rsp_valid), .rsp_ready(ic_rsp_ready), .rsp_rdata(ic_data), .rsp_error(ic_error),
            .mem_valid(back_valid[0]), .mem_write(back_write[0]), .mem_addr(back_addr[63:0]),
            .mem_wdata(back_wdata[63:0]), .mem_wstrb(back_mask[7:0]),
            .mem_rsp_ready(back_rsp_ready[0]), .mem_ready(back_ready[0]),
            .mem_rsp_valid(back_rsp_valid[0]), .mem_rdata(back_rdata[63:0]), .mem_error(back_error[0])
        );
        hammer_v3_dcache #(.LINES(DCACHE_LINES), .WORDS(DMEM_WORDS)) u_dcache (
            .clk(clk), .rst_n(rst_n), .req_valid(dc_valid), .req_ready(dc_ready),
            .req_cmd(dc_cmd), .req_addr(dc_addr), .req_wdata(dc_wdata), .req_wstrb(dc_mask),
            .rsp_valid(dc_rsp_valid), .rsp_ready(dc_rsp_ready), .rsp_rdata(dc_data), .rsp_error(dc_error),
            .mem_valid(back_valid[1]), .mem_write(back_write[1]), .mem_addr(back_addr[127:64]),
            .mem_wdata(back_wdata[127:64]), .mem_wstrb(back_mask[15:8]),
            .mem_rsp_ready(back_rsp_ready[1]), .mem_ready(back_ready[1]),
            .mem_rsp_valid(back_rsp_valid[1]), .mem_rdata(back_rdata[127:64]), .mem_error(back_error[1])
        );
        hammer_v3_accel_bridge #(.DMEM_WORDS(DMEM_WORDS)) u_accel (
            .clk(clk), .rst_n(rst_n), .allow_transaction(allow_accel),
            .exclusive(exclusive), .quiesce_valid(quiesce_valid),
            .quiesce_ready(quiesce_ready), .quiesce_error(quiesce_error),
            .mem_req_valid(back_valid[2]), .mem_req_write(back_write[2]),
            .mem_req_ready(back_ready[2]), .mem_req_addr(back_addr[191:128]),
            .mem_req_wdata(back_wdata[191:128]), .mem_req_wstrb(back_mask[23:16]),
            .mem_rsp_valid(back_rsp_valid[2]), .mem_rsp_ready(back_rsp_ready[2]),
            .mem_rsp_rdata(back_rdata[191:128]), .mem_rsp_error(back_error[2]), .mem_rsp_decerr(back_decerr[2]),
            .s_acc_axi_awid(s_acc_axi_awid), .s_acc_axi_awaddr(s_acc_axi_awaddr),
            .s_acc_axi_awlen(s_acc_axi_awlen), .s_acc_axi_awsize(s_acc_axi_awsize),
            .s_acc_axi_awburst(s_acc_axi_awburst), .s_acc_axi_awlock(s_acc_axi_awlock),
            .s_acc_axi_awcache(s_acc_axi_awcache), .s_acc_axi_awprot(s_acc_axi_awprot),
            .s_acc_axi_awqos(s_acc_axi_awqos), .s_acc_axi_awvalid(s_acc_axi_awvalid),
            .s_acc_axi_awready(s_acc_axi_awready), .s_acc_axi_wdata(s_acc_axi_wdata),
            .s_acc_axi_wstrb(s_acc_axi_wstrb), .s_acc_axi_wlast(s_acc_axi_wlast),
            .s_acc_axi_wvalid(s_acc_axi_wvalid), .s_acc_axi_wready(s_acc_axi_wready),
            .s_acc_axi_bid(s_acc_axi_bid), .s_acc_axi_bresp(s_acc_axi_bresp),
            .s_acc_axi_bvalid(s_acc_axi_bvalid), .s_acc_axi_bready(s_acc_axi_bready),
            .s_acc_axi_arid(s_acc_axi_arid), .s_acc_axi_araddr(s_acc_axi_araddr),
            .s_acc_axi_arlen(s_acc_axi_arlen), .s_acc_axi_arsize(s_acc_axi_arsize),
            .s_acc_axi_arburst(s_acc_axi_arburst), .s_acc_axi_arlock(s_acc_axi_arlock),
            .s_acc_axi_arcache(s_acc_axi_arcache), .s_acc_axi_arprot(s_acc_axi_arprot),
            .s_acc_axi_arqos(s_acc_axi_arqos), .s_acc_axi_arvalid(s_acc_axi_arvalid),
            .s_acc_axi_arready(s_acc_axi_arready), .s_acc_axi_rid(s_acc_axi_rid),
            .s_acc_axi_rdata(s_acc_axi_rdata), .s_acc_axi_rresp(s_acc_axi_rresp),
            .s_acc_axi_rlast(s_acc_axi_rlast), .s_acc_axi_rvalid(s_acc_axi_rvalid),
            .s_acc_axi_rready(s_acc_axi_rready)
        );
        wire mem_valid, mem_ready, mem_write, mem_rsp_valid, mem_rsp_ready, mem_error, mem_decerr;
        wire [63:0] mem_addr, mem_wdata, mem_data;
        wire [7:0] mem_mask;
        wire [2:0] mem_prot;
        hammer_v3_fabric #(.IMEM_WORDS(IMEM_WORDS), .DMEM_WORDS(DMEM_WORDS)) u_fabric (
            .clk(clk), .rst_n(rst_n), .req_valid(back_valid), .req_ready(back_ready),
            .req_write(back_write), .req_addr(back_addr), .req_wdata(back_wdata),
            .req_wstrb(back_mask), .req_prot(back_prot), .rsp_valid(back_rsp_valid),
            .rsp_ready(back_rsp_ready), .rsp_rdata(back_rdata), .rsp_error(back_error), .rsp_decerr(back_decerr),
            .h_imem(h_imem), .h_dmem(h_dmem), .h_write(host_write), .h_addr(host_addr),
            .h_wdata(host_wdata), .h_wstrb(host_wstrb), .h_imem_data(h_imem_data), .h_dmem_data(h_dmem_data),
            .mem_valid(mem_valid), .mem_ready(mem_ready), .mem_write(mem_write),
            .mem_addr(mem_addr), .mem_wdata(mem_wdata), .mem_wstrb(mem_mask), .mem_prot(mem_prot),
            .mem_rsp_valid(mem_rsp_valid), .mem_rsp_ready(mem_rsp_ready),
            .mem_rdata(mem_data), .mem_error(mem_error), .mem_decerr(mem_decerr)
        );
        hammer_v3_axi_master u_mem_axi (
            .clk(clk), .rst_n(rst_n), .req_valid(mem_valid), .req_ready(mem_ready),
            .req_write(mem_write), .req_addr(mem_addr), .req_wdata(mem_wdata),
            .req_wstrb(mem_mask), .req_prot(mem_prot), .rsp_valid(mem_rsp_valid),
            .rsp_ready(mem_rsp_ready), .rsp_rdata(mem_data), .rsp_error(mem_error), .rsp_decerr(mem_decerr),
            .m_mem_axi_awid(m_mem_axi_awid), .m_mem_axi_awaddr(m_mem_axi_awaddr),
            .m_mem_axi_awlen(m_mem_axi_awlen), .m_mem_axi_awsize(m_mem_axi_awsize),
            .m_mem_axi_awburst(m_mem_axi_awburst), .m_mem_axi_awlock(m_mem_axi_awlock),
            .m_mem_axi_awcache(m_mem_axi_awcache), .m_mem_axi_awprot(m_mem_axi_awprot),
            .m_mem_axi_awqos(m_mem_axi_awqos), .m_mem_axi_awvalid(m_mem_axi_awvalid),
            .m_mem_axi_awready(m_mem_axi_awready), .m_mem_axi_wdata(m_mem_axi_wdata),
            .m_mem_axi_wstrb(m_mem_axi_wstrb), .m_mem_axi_wlast(m_mem_axi_wlast),
            .m_mem_axi_wvalid(m_mem_axi_wvalid), .m_mem_axi_wready(m_mem_axi_wready),
            .m_mem_axi_bid(m_mem_axi_bid), .m_mem_axi_bresp(m_mem_axi_bresp),
            .m_mem_axi_bvalid(m_mem_axi_bvalid), .m_mem_axi_bready(m_mem_axi_bready),
            .m_mem_axi_arid(m_mem_axi_arid), .m_mem_axi_araddr(m_mem_axi_araddr),
            .m_mem_axi_arlen(m_mem_axi_arlen), .m_mem_axi_arsize(m_mem_axi_arsize),
            .m_mem_axi_arburst(m_mem_axi_arburst), .m_mem_axi_arlock(m_mem_axi_arlock),
            .m_mem_axi_arcache(m_mem_axi_arcache), .m_mem_axi_arprot(m_mem_axi_arprot),
            .m_mem_axi_arqos(m_mem_axi_arqos), .m_mem_axi_arvalid(m_mem_axi_arvalid),
            .m_mem_axi_arready(m_mem_axi_arready), .m_mem_axi_rid(m_mem_axi_rid),
            .m_mem_axi_rdata(m_mem_axi_rdata), .m_mem_axi_rresp(m_mem_axi_rresp),
            .m_mem_axi_rlast(m_mem_axi_rlast), .m_mem_axi_rvalid(m_mem_axi_rvalid),
            .m_mem_axi_rready(m_mem_axi_rready)
        );
        assign quiesce_ready = rst_n && maintenance_state == MDONE && maintenance_accel;
        assign quiesce_error = quiesce_ready && maintenance_error;
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                launch_pending <= 0;
                resume_pending <= 0;
                progress_token <= 1;
                host_pending <= 0;
                host_wait <= 0;
                host_error_q <= 0;
                host_imem_q <= 0;
                host_read_q <= 0;
                host_dirty <= 0;
                maintenance_fault <= 0;
                host_rsp_valid <= 0;
                host_rsp_error <= 0;
                host_rdata <= 0;
                maintenance_state <= MIDLE;
                maintenance_accel <= 0;
                maintenance_error <= 0;
            end else begin
                host_rsp_valid <= 0;
                host_rsp_error <= 0;
                host_rdata <= 0;
                if (start_accept) launch_pending <= 1;
                if (core_start || (halt_req && core_halted)) launch_pending <= 0;
                if (exclusive && !core_halted) resume_pending <= 1;
                if (core_start || halt_req) resume_pending <= 0;
                if (retire_valid || trap_valid) progress_token <= 1;
                if (accel_accept || exclusive) progress_token <= 0;
                if (host_accept) begin
                    host_pending <= 1;
                    host_error_q <= host_bad;
                    host_imem_q <= host_imem;
                    host_wait <= host_write && !host_bad;
                    if (host_write && !host_bad) host_dirty <= 1;
                end
                if (host_pending) begin
                    host_pending <= 0;
                    host_read_q <= host_imem_q ? h_imem_data : h_dmem_data;
                    if (!host_wait) begin
                        host_rsp_valid <= 1;
                        host_rsp_error <= host_error_q;
                        host_rdata <= host_error_q ? 64'b0 :
                            host_imem_q ? h_imem_data : h_dmem_data;
                    end
                end
                if (host_wait && !host_pending && maintenance_idle) begin
                    host_wait <= 0;
                    host_rsp_valid <= 1;
                    host_rsp_error <= maintenance_fault;
                end
                case (maintenance_state)
                    MIDLE: if (core_halted && (host_dirty || quiesce_valid)) begin
                        maintenance_accel <= quiesce_valid;
                        maintenance_error <= 0;
                        host_dirty <= 0;
                        maintenance_state <= MDREQ;
                    end
                    MDREQ: if (da_ready[2]) maintenance_state <= MDWAIT;
                    MDWAIT: if (da_rsp_valid[2]) begin
                        maintenance_error <= da_error[2];
                        maintenance_state <= MIREQ;
                    end
                    MIREQ: if (ia_ready[1]) maintenance_state <= MIWAIT;
                    MIWAIT: if (ia_rsp_valid[1]) begin
                        maintenance_error <= maintenance_error || ia_error[1];
                        maintenance_state <= MDONE;
                    end
                    MDONE: begin
                        if (!maintenance_accel) begin
                            maintenance_fault <= maintenance_fault || maintenance_error;
                            maintenance_state <= MIDLE;
                        end else if (quiesce_valid) maintenance_state <= MIDLE;
                    end
                    default: maintenance_state <= MIDLE;
                endcase
            end
        end
    end endgenerate
endmodule
