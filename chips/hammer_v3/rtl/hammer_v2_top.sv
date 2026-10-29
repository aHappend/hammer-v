module hammer_v2_top #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16,
    parameter integer ICACHE_LINES = 64,
    parameter integer DCACHE_LINES = 64,
    parameter integer LEGACY_TRAPS = 0
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
    output wire trap_interrupt
);
    initial begin
        if (IMEM_WORDS < 1 || IMEM_WORDS > 16384)
            $fatal(1, "PARAMETER ERROR: IMEM_WORDS must be 1..16384");
        if (DMEM_WORDS < 1 || DMEM_WORDS > 8192)
            $fatal(1, "PARAMETER ERROR: DMEM_WORDS must be 1..8192");
        if (PRED_MODE != 0 && PRED_MODE != 1)
            $fatal(1, "PARAMETER ERROR: PRED_MODE must be 0 or 1");
        if (BTB_ENTRIES != 1 && BTB_ENTRIES != 4 &&
            BTB_ENTRIES != 16 && BTB_ENTRIES != 64)
            $fatal(1, "PARAMETER ERROR: BTB_ENTRIES must be 1,4,16,64");
        if (ICACHE_LINES != 1 && ICACHE_LINES != 4 &&
            ICACHE_LINES != 16 && ICACHE_LINES != 64)
            $fatal(1, "PARAMETER ERROR: ICACHE_LINES must be 1,4,16,64");
        if (DCACHE_LINES != 1 && DCACHE_LINES != 4 &&
            DCACHE_LINES != 16 && DCACHE_LINES != 64)
            $fatal(1, "PARAMETER ERROR: DCACHE_LINES must be 1,4,16,64");
        if (LEGACY_TRAPS != 0 && LEGACY_TRAPS != 1)
            $fatal(1, "PARAMETER ERROR: LEGACY_TRAPS must be 0 or 1");
    end
    localparam [63:0] IMEM_BYTES = IMEM_WORDS * 64'd4;
    localparam [63:0] DMEM_BYTES = DMEM_WORDS * 64'd8;
    reg host_pending, host_error_q, host_imem_q, host_write_q;
    reg launch_pending, invalidate_i, invalidate_d, maintenance_fault;
    reg [1:0] host_i_state, host_d_state;
    wire core_halted;
    wire host_accept = host_valid && host_ready;
    wire imem_bad = |host_addr[1:0] ||
        {32'b0,host_addr} >= IMEM_BYTES ||
        |host_wdata[63:32] || |host_wstrb[7:4];
    wire dmem_bad = |host_addr[2:0] || {32'b0,host_addr} >= DMEM_BYTES;
    wire host_bad = (host_imem ? imem_bad : dmem_bad) || maintenance_fault;
    wire h_imem = host_accept && host_imem && !host_bad;
    wire h_dmem = host_accept && !host_imem && !host_bad;
    wire [63:0] h_imem_data, h_dmem_data;
    assign halted = !rst_n || (core_halted && !launch_pending);
    assign host_ready = rst_n && halted && !host_pending && !host_rsp_valid;
    wire start_accept = rst_n && start && halted &&
        !(LEGACY_TRAPS && trap_valid) &&
        !host_pending && !host_rsp_valid && !host_valid && !halt_req;
    wire maintenance_idle = host_i_state == 0 && host_d_state == 0 &&
        !invalidate_i && !invalidate_d && !maintenance_fault;
    wire core_start = rst_n && core_halted && !halt_req &&
        maintenance_idle && !host_pending && !host_rsp_valid && !host_valid &&
        (start_accept || launch_pending);

    wire ci_valid, ci_ready, ci_rsp_valid, ci_rsp_ready, ci_error;
    wire [1:0] ci_cmd;
    wire [63:0] ci_addr, ci_data;
    wire cd_valid, cd_ready, cd_rsp_valid, cd_rsp_ready, cd_error;
    wire [1:0] cd_cmd;
    wire [63:0] cd_addr, cd_wdata, cd_data;
    wire [7:0] cd_mask;
    wire ic_ready, ic_rsp_valid, ic_error, dc_ready, dc_rsp_valid, dc_error;
    wire [63:0] ic_data, dc_data;
    wire hi_request = core_halted && host_i_state == 1;
    wire hd_request = core_halted && host_d_state == 1;
    wire hi_response = core_halted && host_i_state == 2 && ic_rsp_valid;
    wire hd_response = core_halted && host_d_state == 2 && dc_rsp_valid;
    assign ci_ready = !core_halted && ic_ready;
    assign ci_rsp_valid = !core_halted && ic_rsp_valid;
    assign ci_data = ci_rsp_valid ? ic_data : 64'b0;
    assign ci_error = ci_rsp_valid && ic_error;
    assign cd_ready = !core_halted && dc_ready;
    assign cd_rsp_valid = !core_halted && dc_rsp_valid;
    assign cd_data = cd_rsp_valid ? dc_data : 64'b0;
    assign cd_error = cd_rsp_valid && dc_error;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            host_pending <= 1'b0;
            host_error_q <= 1'b0;
            host_imem_q <= 1'b0;
            host_write_q <= 1'b0;
            host_rsp_valid <= 1'b0;
            host_rsp_error <= 1'b0;
            host_rdata <= 64'b0;
            launch_pending <= 1'b0;
            invalidate_i <= 1'b0;
            invalidate_d <= 1'b0;
            maintenance_fault <= 1'b0;
            host_i_state <= 2'b0;
            host_d_state <= 2'b0;
        end else begin
            host_rsp_valid <= 1'b0;
            host_rsp_error <= 1'b0;
            host_rdata <= 64'b0;
            if (host_pending) begin
                host_pending <= 1'b0;
                host_rsp_valid <= 1'b1;
                host_rsp_error <= host_error_q;
                if (!host_error_q && !host_write_q)
                    host_rdata <= host_imem_q ? h_imem_data : h_dmem_data;
            end
            if (core_halted && host_i_state == 0 && invalidate_i) begin
                host_i_state <= 2'd1;
                invalidate_i <= 1'b0;
            end
            if (core_halted && host_d_state == 0 && invalidate_d) begin
                host_d_state <= 2'd1;
                invalidate_d <= 1'b0;
            end
            if (hi_request && ic_ready) host_i_state <= 2'd2;
            if (hd_request && dc_ready) host_d_state <= 2'd2;
            if (hi_response) begin
                host_i_state <= 2'b0;
                if (ic_error) maintenance_fault <= 1'b1;
            end
            if (hd_response) begin
                host_d_state <= 2'b0;
                if (dc_error) maintenance_fault <= 1'b1;
            end
            if (host_accept) begin
                host_pending <= 1'b1;
                host_error_q <= host_bad;
                host_imem_q <= host_imem;
                host_write_q <= host_write;
                if (h_imem && host_write) invalidate_i <= 1'b1;
                if (h_dmem && host_write) invalidate_d <= 1'b1;
            end
            if (start_accept) launch_pending <= 1'b1;
            if (core_start || (halt_req && core_halted)) launch_pending <= 1'b0;
        end
    end
    wire a_valid, a_ready, a_write, a_rsp_valid, a_rsp_ready, a_error;
    wire [31:0] a_addr;
    wire [63:0] a_wdata, a_rdata;
    wire [7:0] a_wstrb;
    wire c_valid, c_ready, c_write, c_rsp_valid, c_rsp_ready, c_error;
    wire [1:0] c_size;
    wire [63:0] c_addr, c_wdata, c_data, mtime;
    wire [7:0] c_mask;
    wire msip, mtip;
    hammer_v2_core #(
        .IMEM_WORDS(IMEM_WORDS), .DMEM_WORDS(DMEM_WORDS),
        .PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES), .LEGACY_TRAPS(LEGACY_TRAPS)
    ) u_core (
        .clk(clk), .rst_n(rst_n), .start(core_start), .halt_req(halt_req),
        .host_data_write(h_dmem && host_write), .halted(core_halted),
        .irq_msip(msip), .irq_mtip(mtip), .irq_meip(irq_meip), .irq_seip(irq_seip),
        .mtime(mtime), .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata),
        .trap_valid(trap_valid), .trap_pc(trap_pc), .trap_cause(trap_cause),
        .trap_tval(trap_tval), .trap_target_priv(trap_target_priv),
        .trap_interrupt(trap_interrupt), .retire_valid(retire_valid),
        .retire_pc(retire_pc), .retire_next_pc(retire_next_pc),
        .retire_insn(retire_insn), .retire_priv(retire_priv),
        .retire_rd_we(retire_rd_we), .retire_rd(retire_rd),
        .retire_rd_data(retire_rd_data), .retire_mem_valid(retire_mem_valid),
        .retire_mem_write(retire_mem_write), .retire_mem_addr(retire_mem_addr),
        .retire_mem_wmask(retire_mem_wmask), .retire_mem_wdata(retire_mem_wdata),
        .retire_mem_rdata(retire_mem_rdata),
        .stall_load_use(stall_load_use), .stall_mem(stall_mem),
        .stall_muldiv(stall_muldiv), .redirect_valid(redirect_valid),
        .redirect_pc(redirect_pc), .ex_valid(ex_valid), .ex_pc(ex_pc),
        .ex_rs1_sel(ex_rs1_sel), .ex_rs2_sel(ex_rs2_sel), .ex_store_sel(ex_store_sel),
        .i_req_valid(ci_valid), .i_req_ready(ci_ready), .i_req_cmd(ci_cmd),
        .i_req_addr(ci_addr), .i_rsp_valid(ci_rsp_valid), .i_rsp_ready(ci_rsp_ready),
        .i_rsp_rdata(ci_data), .i_rsp_error(ci_error),
        .d_req_valid(cd_valid), .d_req_ready(cd_ready), .d_req_cmd(cd_cmd),
        .d_req_addr(cd_addr), .d_req_wdata(cd_wdata), .d_req_wstrb(cd_mask),
        .d_rsp_valid(cd_rsp_valid), .d_rsp_ready(cd_rsp_ready),
        .d_rsp_rdata(cd_data), .d_rsp_error(cd_error),
        .a_valid(a_valid), .a_ready(a_ready), .a_write(a_write), .a_addr(a_addr),
        .a_wdata(a_wdata), .a_wstrb(a_wstrb), .a_rsp_valid(a_rsp_valid),
        .a_rsp_ready(a_rsp_ready), .a_rdata(a_rdata), .a_error(a_error),
        .c_req_valid(c_valid), .c_req_ready(c_ready), .c_req_write(c_write),
        .c_req_size(c_size), .c_req_addr(c_addr), .c_req_wdata(c_wdata),
        .c_req_wstrb(c_mask), .c_rsp_valid(c_rsp_valid), .c_rsp_ready(c_rsp_ready),
        .c_rsp_rdata(c_data), .c_rsp_error(c_error)
    );
    wire im_valid, im_ready, im_write, im_rsp_valid, im_rsp_ready, im_error;
    wire [63:0] im_addr, im_wdata, im_data;
    wire [7:0] im_mask;
    wire dm_valid, dm_ready, dm_write, dm_rsp_valid, dm_rsp_ready, dm_error;
    wire [63:0] dm_addr, dm_wdata, dm_data;
    wire [7:0] dm_mask;
    hammer_v2_icache #(.LINES(ICACHE_LINES), .WORDS(IMEM_WORDS)) u_icache (
        .clk(clk), .rst_n(rst_n),
        .req_valid(core_halted ? hi_request : ci_valid),
        .req_cmd(core_halted ? 2'b11 : ci_cmd),
        .req_addr(core_halted ? 64'b0 : ci_addr),
        .req_wdata(64'b0), .req_wstrb(8'b0),
        .req_ready(ic_ready), .rsp_valid(ic_rsp_valid), .rsp_rdata(ic_data),
        .rsp_error(ic_error), .rsp_ready(core_halted ? host_i_state == 2 : ci_rsp_ready),
        .mem_valid(im_valid), .mem_write(im_write), .mem_addr(im_addr),
        .mem_wdata(im_wdata), .mem_wstrb(im_mask), .mem_rsp_ready(im_rsp_ready),
        .mem_ready(im_ready), .mem_rsp_valid(im_rsp_valid),
        .mem_rdata(im_data), .mem_error(im_error)
    );
    hammer_v2_dcache #(.LINES(DCACHE_LINES), .WORDS(DMEM_WORDS)) u_dcache (
        .clk(clk), .rst_n(rst_n),
        .req_valid(core_halted ? hd_request : cd_valid),
        .req_cmd(core_halted ? 2'b11 : cd_cmd),
        .req_addr(core_halted ? 64'b0 : cd_addr),
        .req_wdata(core_halted ? 64'b0 : cd_wdata),
        .req_wstrb(core_halted ? 8'b0 : cd_mask),
        .req_ready(dc_ready), .rsp_valid(dc_rsp_valid), .rsp_rdata(dc_data),
        .rsp_error(dc_error), .rsp_ready(core_halted ? host_d_state == 2 : cd_rsp_ready),
        .mem_valid(dm_valid), .mem_write(dm_write), .mem_addr(dm_addr),
        .mem_wdata(dm_wdata), .mem_wstrb(dm_mask), .mem_rsp_ready(dm_rsp_ready),
        .mem_ready(dm_ready), .mem_rsp_valid(dm_rsp_valid),
        .mem_rdata(dm_data), .mem_error(dm_error)
    );
    hammer_v2_imem #(.WORDS(IMEM_WORDS)) u_imem (
        .clk(clk), .rst_n(rst_n), .req_valid(im_valid), .req_ready(im_ready),
        .req_write(im_write), .req_addr(im_addr), .req_wdata(im_wdata),
        .req_wstrb(im_mask), .rsp_valid(im_rsp_valid), .rsp_ready(im_rsp_ready),
        .rsp_rdata(im_data), .rsp_error(im_error),
        .h_req(h_imem), .h_write(host_write), .h_addr(host_addr),
        .h_wdata(host_wdata), .h_wstrb(host_wstrb), .h_rdata(h_imem_data)
    );
    hammer_v2_dmem #(.WORDS(DMEM_WORDS)) u_dmem (
        .clk(clk), .rst_n(rst_n), .req_valid(dm_valid), .req_ready(dm_ready),
        .req_write(dm_write), .req_addr(dm_addr), .req_wdata(dm_wdata),
        .req_wstrb(dm_mask), .rsp_valid(dm_rsp_valid), .rsp_ready(dm_rsp_ready),
        .rsp_rdata(dm_data), .rsp_error(dm_error),
        .h_req(h_dmem), .h_write(host_write), .h_addr(host_addr),
        .h_wdata(host_wdata), .h_wstrb(host_wstrb), .h_rdata(h_dmem_data)
    );
    hammer_v2_clint u_clint (
        .clk(clk), .rst_n(rst_n), .req_valid(c_valid), .req_ready(c_ready),
        .req_write(c_write), .req_size(c_size), .req_addr(c_addr),
        .req_wdata(c_wdata), .req_wstrb(c_mask), .rsp_valid(c_rsp_valid),
        .rsp_ready(c_rsp_ready), .rsp_rdata(c_data), .rsp_error(c_error),
        .mtime(mtime), .irq_msip(msip), .irq_mtip(mtip)
    );
    hammer_v2_axi_lite u_axi (
        .clk(clk), .rst_n(rst_n), .a_valid(a_valid), .a_ready(a_ready),
        .a_write(a_write), .a_addr(a_addr), .a_wdata(a_wdata), .a_wstrb(a_wstrb),
        .a_rsp_valid(a_rsp_valid), .a_rsp_ready(a_rsp_ready),
        .a_rdata(a_rdata), .a_error(a_error),
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
endmodule
