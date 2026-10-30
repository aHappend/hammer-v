module hammer_v4_top #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16,
    parameter integer ICACHE_LINES = 64,
    parameter integer DCACHE_LINES = 64,
    parameter integer LEGACY_TRAPS = 0,
    parameter integer ITLB_ENTRIES = 8,
    parameter integer DTLB_ENTRIES = 8,
    parameter integer BOOT_ENABLE = 1
) (
    input wire clk, rst_n, start,
    input wire host_valid, host_write, host_imem,
    input wire [31:0] host_addr,
    input wire [63:0] host_wdata,
    input wire [7:0] host_wstrb,
    input wire [4:0] dbg_raddr,
    output wire halted, host_ready,
    output wire host_rsp_valid, host_rsp_error,
    output wire [63:0] host_rdata,
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
    input wire s_acc_axi_rready,
    output wire boot_ready, boot_error
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
        (DTLB_ENTRIES == 1 || DTLB_ENTRIES == 4 || DTLB_ENTRIES == 8 || DTLB_ENTRIES == 16) &&
        (BOOT_ENABLE == 0 || BOOT_ENABLE == 1) &&
        (BOOT_ENABLE == 0 || (IMEM_WORDS >= 32 && LEGACY_TRAPS == 0));
    initial if (!LEGAL)
        $fatal(1, "PARAMETER ERROR: illegal HAMMER-V4 configuration");

    generate if (LEGAL) begin : g_legal
        localparam [2:0] IDLE=0, ISSUE=1, WAIT_RESPONSE=2, DONE=3, FAILED=4;
        reg [2:0] state;
        reg [4:0] word_index;
        reg ready_q, error_q;
        wire [31:0] rom_data;
        wire parent_ready, parent_rsp_valid, parent_rsp_error;
        wire parent_acc_awready, parent_acc_wready, parent_acc_arready;
        wire [63:0] parent_rdata;
        wire external_enable = rst_n && ready_q && !error_q;
        wire loader_valid = rst_n && BOOT_ENABLE == 1 && state == ISSUE;
        wire parent_host_valid = external_enable ? host_valid : loader_valid;
        assign boot_ready = rst_n && ready_q;
        assign boot_error = rst_n && error_q;
        assign host_ready = external_enable && parent_ready;
        assign host_rsp_valid = external_enable && parent_rsp_valid;
        assign host_rsp_error = host_rsp_valid && parent_rsp_error;
        assign host_rdata = host_rsp_valid ? parent_rdata : 64'b0;

        hammer_v4_boot_rom u_boot_rom (
            .word_addr(word_index), .word_data(rom_data)
        );
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                state <= IDLE;
                word_index <= 0;
                ready_q <= 0;
                error_q <= 0;
            end else begin
                case (state)
                    IDLE: begin
                        if (BOOT_ENABLE == 1) state <= ISSUE;
                        else begin
                            ready_q <= 1;
                            state <= DONE;
                        end
                    end
                    ISSUE: if (parent_ready) state <= WAIT_RESPONSE;
                    WAIT_RESPONSE: if (parent_rsp_valid) begin
                        if (parent_rsp_error) begin
                            error_q <= 1;
                            state <= FAILED;
                        end else if (word_index == 5'd31) begin
                            ready_q <= 1;
                            state <= DONE;
                        end else begin
                            word_index <= word_index + 5'd1;
                            state <= ISSUE;
                        end
                    end
                    DONE: begin end
                    FAILED: begin end
                    default: begin
                        ready_q <= 0;
                        error_q <= 1;
                        state <= FAILED;
                    end
                endcase
            end
        end

        hammer_v3_top #(
            .IMEM_WORDS(IMEM_WORDS), .DMEM_WORDS(DMEM_WORDS),
            .PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES),
            .ICACHE_LINES(ICACHE_LINES), .DCACHE_LINES(DCACHE_LINES),
            .LEGACY_TRAPS(LEGACY_TRAPS),
            .ITLB_ENTRIES(ITLB_ENTRIES), .DTLB_ENTRIES(DTLB_ENTRIES)
        ) u_v3 (
            .clk(clk), .rst_n(rst_n), .start(start && external_enable),
            .host_valid(parent_host_valid),
            .host_write(external_enable ? host_write : 1'b1),
            .host_imem(external_enable ? host_imem : 1'b1),
            .host_addr(external_enable ? host_addr : {25'b0,word_index,2'b0}),
            .host_wdata(external_enable ? host_wdata : {32'b0,rom_data}),
            .host_wstrb(external_enable ? host_wstrb : 8'h0f),
            .host_ready(parent_ready), .host_rsp_valid(parent_rsp_valid),
            .host_rsp_error(parent_rsp_error), .host_rdata(parent_rdata),
            .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata), .halted(halted),
            .halt_req(halt_req), .irq_meip(irq_meip), .irq_seip(irq_seip),
            .trap_valid(trap_valid), .trap_pc(trap_pc), .trap_cause(trap_cause),
            .retire_valid(retire_valid), .retire_pc(retire_pc),
            .retire_next_pc(retire_next_pc), .retire_insn(retire_insn),
            .retire_rd_we(retire_rd_we), .retire_rd(retire_rd),
            .retire_rd_data(retire_rd_data), .retire_mem_valid(retire_mem_valid),
            .retire_mem_write(retire_mem_write), .retire_mem_addr(retire_mem_addr),
            .retire_mem_wmask(retire_mem_wmask), .retire_mem_wdata(retire_mem_wdata),
            .retire_mem_rdata(retire_mem_rdata), .stall_load_use(stall_load_use),
            .stall_mem(stall_mem), .stall_muldiv(stall_muldiv),
            .redirect_valid(redirect_valid), .redirect_pc(redirect_pc),
            .ex_valid(ex_valid), .ex_pc(ex_pc), .ex_rs1_sel(ex_rs1_sel),
            .ex_rs2_sel(ex_rs2_sel), .ex_store_sel(ex_store_sel),
            .retire_priv(retire_priv), .trap_tval(trap_tval),
            .trap_target_priv(trap_target_priv), .trap_interrupt(trap_interrupt),
            .uart_rx(uart_rx), .uart_tx(uart_tx), .plic_sources(plic_sources),
            .m_axi_awaddr(m_axi_awaddr), .m_axi_awprot(m_axi_awprot),
            .m_axi_awvalid(m_axi_awvalid), .m_axi_wdata(m_axi_wdata),
            .m_axi_wstrb(m_axi_wstrb), .m_axi_wvalid(m_axi_wvalid),
            .m_axi_bready(m_axi_bready), .m_axi_araddr(m_axi_araddr),
            .m_axi_arprot(m_axi_arprot), .m_axi_arvalid(m_axi_arvalid),
            .m_axi_rready(m_axi_rready), .m_axi_awready(m_axi_awready),
            .m_axi_wready(m_axi_wready), .m_axi_bresp(m_axi_bresp),
            .m_axi_bvalid(m_axi_bvalid), .m_axi_arready(m_axi_arready),
            .m_axi_rdata(m_axi_rdata), .m_axi_rresp(m_axi_rresp),
            .m_axi_rvalid(m_axi_rvalid),
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
            .m_mem_axi_rready(m_mem_axi_rready),
            .s_acc_axi_awid(s_acc_axi_awid), .s_acc_axi_awaddr(s_acc_axi_awaddr),
            .s_acc_axi_awlen(s_acc_axi_awlen), .s_acc_axi_awsize(s_acc_axi_awsize),
            .s_acc_axi_awburst(s_acc_axi_awburst), .s_acc_axi_awlock(s_acc_axi_awlock),
            .s_acc_axi_awcache(s_acc_axi_awcache), .s_acc_axi_awprot(s_acc_axi_awprot),
            .s_acc_axi_awqos(s_acc_axi_awqos),
            .s_acc_axi_awvalid(s_acc_axi_awvalid && external_enable),
            .s_acc_axi_awready(parent_acc_awready),
            .s_acc_axi_wdata(s_acc_axi_wdata), .s_acc_axi_wstrb(s_acc_axi_wstrb),
            .s_acc_axi_wlast(s_acc_axi_wlast),
            .s_acc_axi_wvalid(s_acc_axi_wvalid && external_enable),
            .s_acc_axi_wready(parent_acc_wready),
            .s_acc_axi_bid(s_acc_axi_bid), .s_acc_axi_bresp(s_acc_axi_bresp),
            .s_acc_axi_bvalid(s_acc_axi_bvalid), .s_acc_axi_bready(s_acc_axi_bready),
            .s_acc_axi_arid(s_acc_axi_arid), .s_acc_axi_araddr(s_acc_axi_araddr),
            .s_acc_axi_arlen(s_acc_axi_arlen), .s_acc_axi_arsize(s_acc_axi_arsize),
            .s_acc_axi_arburst(s_acc_axi_arburst), .s_acc_axi_arlock(s_acc_axi_arlock),
            .s_acc_axi_arcache(s_acc_axi_arcache), .s_acc_axi_arprot(s_acc_axi_arprot),
            .s_acc_axi_arqos(s_acc_axi_arqos),
            .s_acc_axi_arvalid(s_acc_axi_arvalid && external_enable),
            .s_acc_axi_arready(parent_acc_arready),
            .s_acc_axi_rid(s_acc_axi_rid), .s_acc_axi_rdata(s_acc_axi_rdata),
            .s_acc_axi_rresp(s_acc_axi_rresp), .s_acc_axi_rlast(s_acc_axi_rlast),
            .s_acc_axi_rvalid(s_acc_axi_rvalid), .s_acc_axi_rready(s_acc_axi_rready)
        );
        assign s_acc_axi_awready = external_enable && parent_acc_awready;
        assign s_acc_axi_wready = external_enable && parent_acc_wready;
        assign s_acc_axi_arready = external_enable && parent_acc_arready;
    end else begin : g_illegal
        assign boot_ready = 1'b0;
        assign boot_error = 1'b0;
        assign halted = 1'b1;
        assign host_ready = 1'b0;
        assign host_rsp_valid = 1'b0;
        assign host_rsp_error = 1'b0;
        assign host_rdata = 64'b0;
        assign dbg_rdata = 64'b0;
        assign trap_valid = 1'b0;
        assign trap_pc = 64'b0;
        assign trap_cause = 64'b0;
        assign trap_tval = 64'b0;
        assign trap_target_priv = 2'b0;
        assign trap_interrupt = 1'b0;
        assign retire_valid = 1'b0;
        assign retire_pc = 64'b0;
        assign retire_next_pc = 64'b0;
        assign retire_insn = 32'b0;
        assign retire_priv = 2'b0;
        assign retire_rd_we = 1'b0;
        assign retire_rd = 5'b0;
        assign retire_rd_data = 64'b0;
        assign retire_mem_valid = 1'b0;
        assign retire_mem_write = 1'b0;
        assign retire_mem_addr = 64'b0;
        assign retire_mem_wmask = 8'b0;
        assign retire_mem_wdata = 64'b0;
        assign retire_mem_rdata = 64'b0;
        assign stall_load_use = 1'b0;
        assign stall_mem = 1'b0;
        assign stall_muldiv = 1'b0;
        assign redirect_valid = 1'b0;
        assign redirect_pc = 64'b0;
        assign ex_valid = 1'b0;
        assign ex_pc = 64'b0;
        assign ex_rs1_sel = 2'b0;
        assign ex_rs2_sel = 2'b0;
        assign ex_store_sel = 2'b0;
        assign uart_tx = 1'b1;
        assign m_axi_awaddr = 32'b0;
        assign m_axi_awprot = 3'b0;
        assign m_axi_awvalid = 1'b0;
        assign m_axi_wdata = 64'b0;
        assign m_axi_wstrb = 8'b0;
        assign m_axi_wvalid = 1'b0;
        assign m_axi_bready = 1'b0;
        assign m_axi_araddr = 32'b0;
        assign m_axi_arprot = 3'b0;
        assign m_axi_arvalid = 1'b0;
        assign m_axi_rready = 1'b0;
        assign m_mem_axi_awid = 4'b0;
        assign m_mem_axi_awaddr = 64'b0;
        assign m_mem_axi_awlen = 8'b0;
        assign m_mem_axi_awsize = 3'b0;
        assign m_mem_axi_awburst = 2'b0;
        assign m_mem_axi_awlock = 1'b0;
        assign m_mem_axi_awcache = 4'b0;
        assign m_mem_axi_awprot = 3'b0;
        assign m_mem_axi_awqos = 4'b0;
        assign m_mem_axi_awvalid = 1'b0;
        assign m_mem_axi_wdata = 64'b0;
        assign m_mem_axi_wstrb = 8'b0;
        assign m_mem_axi_wlast = 1'b0;
        assign m_mem_axi_wvalid = 1'b0;
        assign m_mem_axi_bready = 1'b0;
        assign m_mem_axi_arid = 4'b0;
        assign m_mem_axi_araddr = 64'b0;
        assign m_mem_axi_arlen = 8'b0;
        assign m_mem_axi_arsize = 3'b0;
        assign m_mem_axi_arburst = 2'b0;
        assign m_mem_axi_arlock = 1'b0;
        assign m_mem_axi_arcache = 4'b0;
        assign m_mem_axi_arprot = 3'b0;
        assign m_mem_axi_arqos = 4'b0;
        assign m_mem_axi_arvalid = 1'b0;
        assign m_mem_axi_rready = 1'b0;
        assign s_acc_axi_awready = 1'b0;
        assign s_acc_axi_wready = 1'b0;
        assign s_acc_axi_bid = 4'b0;
        assign s_acc_axi_bresp = 2'b0;
        assign s_acc_axi_bvalid = 1'b0;
        assign s_acc_axi_arready = 1'b0;
        assign s_acc_axi_rid = 4'b0;
        assign s_acc_axi_rdata = 64'b0;
        assign s_acc_axi_rresp = 2'b0;
        assign s_acc_axi_rlast = 1'b0;
        assign s_acc_axi_rvalid = 1'b0;
    end endgenerate
endmodule
