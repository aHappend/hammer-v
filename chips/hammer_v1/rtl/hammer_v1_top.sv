module hammer_v1_top #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192,
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16
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
    input wire m_axi_rvalid
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
    end
    localparam [63:0] IMEM_BYTES = IMEM_WORDS * 64'd4;
    localparam [63:0] DMEM_BYTES = DMEM_WORDS * 64'd8;
    reg host_pending, host_error_q, host_imem_q, host_write_q;
    wire host_accept = host_valid && host_ready;
    wire imem_bad = host_addr[1:0] != 0 ||
        {32'b0, host_addr} >= IMEM_BYTES ||
        host_wdata[63:32] != 0 || host_wstrb[7:4] != 0;
    wire dmem_bad = host_addr[2:0] != 0 ||
        {32'b0, host_addr} >= DMEM_BYTES;
    wire host_bad = host_imem ? imem_bad : dmem_bad;
    wire h_imem = host_accept && host_imem && !host_bad;
    wire h_dmem = host_accept && !host_imem && !host_bad;
    wire [63:0] h_imem_data, h_dmem_data;
    assign host_ready = rst_n && halted && !host_pending && !host_rsp_valid;
    wire core_start = rst_n && start && halted && !trap_valid &&
                      !host_pending && !host_rsp_valid && !host_valid;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            host_pending <= 1'b0;
            host_error_q <= 1'b0;
            host_imem_q <= 1'b0;
            host_write_q <= 1'b0;
            host_rsp_valid <= 1'b0;
            host_rsp_error <= 1'b0;
            host_rdata <= 64'b0;
        end else begin
            host_rsp_valid <= 1'b0;
            host_rsp_error <= 1'b0;
            host_rdata <= 64'b0;
            if (host_pending) begin
                host_pending <= 1'b0;
                host_rsp_valid <= 1'b1;
                host_rsp_error <= host_error_q;
                if (!host_error_q && !host_write_q) begin
                    if (host_imem_q) host_rdata <= h_imem_data;
                    else host_rdata <= h_dmem_data;
                end
            end
            if (host_accept) begin
                host_pending <= 1'b1;
                host_error_q <= host_bad;
                host_imem_q <= host_imem;
                host_write_q <= host_write;
            end
        end
    end

    wire i_req, i_error;
    wire [63:0] i_addr;
    wire [31:0] i_data;
    wire d_req, d_write;
    wire [63:0] d_addr, d_wdata, d_rdata;
    wire [7:0] d_wstrb;
    wire a_valid, a_ready, a_write, a_rsp_valid, a_rsp_ready, a_error;
    wire [31:0] a_addr;
    wire [63:0] a_wdata, a_rdata;
    wire [7:0] a_wstrb;
    hammer_v1_core #(
        .IMEM_WORDS(IMEM_WORDS), .DMEM_WORDS(DMEM_WORDS),
        .PRED_MODE(PRED_MODE), .BTB_ENTRIES(BTB_ENTRIES)
    ) u_core (
        .clk(clk), .rst_n(rst_n), .start(core_start), .halted(halted),
        .dbg_raddr(dbg_raddr), .dbg_rdata(dbg_rdata),
        .trap_valid(trap_valid), .trap_pc(trap_pc), .trap_cause(trap_cause),
        .retire_valid(retire_valid), .retire_pc(retire_pc),
        .retire_next_pc(retire_next_pc), .retire_insn(retire_insn),
        .retire_rd_we(retire_rd_we), .retire_rd(retire_rd),
        .retire_rd_data(retire_rd_data), .retire_mem_valid(retire_mem_valid),
        .retire_mem_write(retire_mem_write), .retire_mem_addr(retire_mem_addr),
        .retire_mem_wmask(retire_mem_wmask), .retire_mem_wdata(retire_mem_wdata),
        .retire_mem_rdata(retire_mem_rdata),
        .stall_load_use(stall_load_use), .stall_mem(stall_mem),
        .stall_muldiv(stall_muldiv), .redirect_valid(redirect_valid),
        .redirect_pc(redirect_pc), .ex_valid(ex_valid), .ex_pc(ex_pc),
        .ex_rs1_sel(ex_rs1_sel), .ex_rs2_sel(ex_rs2_sel),
        .ex_store_sel(ex_store_sel),
        .i_req(i_req), .i_addr(i_addr), .i_data(i_data), .i_error(i_error),
        .d_req(d_req), .d_write(d_write), .d_addr(d_addr),
        .d_wdata(d_wdata), .d_wstrb(d_wstrb), .d_rdata(d_rdata),
        .a_valid(a_valid), .a_ready(a_ready), .a_write(a_write),
        .a_addr(a_addr), .a_wdata(a_wdata), .a_wstrb(a_wstrb),
        .a_rsp_valid(a_rsp_valid), .a_rsp_ready(a_rsp_ready),
        .a_rdata(a_rdata), .a_error(a_error)
    );
    hammer_v1_imem #(.WORDS(IMEM_WORDS)) u_imem (
        .clk(clk), .rst_n(rst_n), .i_req(i_req), .i_addr(i_addr),
        .i_data(i_data), .i_error(i_error), .h_req(h_imem),
        .h_write(host_write), .h_addr(host_addr),
        .h_wdata(host_wdata), .h_wstrb(host_wstrb), .h_rdata(h_imem_data)
    );
    hammer_v1_dmem #(.WORDS(DMEM_WORDS)) u_dmem (
        .clk(clk), .rst_n(rst_n), .d_req(d_req), .d_write(d_write),
        .d_addr(d_addr), .d_wdata(d_wdata), .d_wstrb(d_wstrb),
        .d_rdata(d_rdata), .h_req(h_dmem), .h_write(host_write),
        .h_addr(host_addr), .h_wdata(host_wdata), .h_wstrb(host_wstrb),
        .h_rdata(h_dmem_data)
    );
    hammer_v1_axi_lite u_axi (
        .clk(clk), .rst_n(rst_n), .a_valid(a_valid), .a_ready(a_ready),
        .a_write(a_write), .a_addr(a_addr), .a_wdata(a_wdata),
        .a_wstrb(a_wstrb), .a_rsp_valid(a_rsp_valid), .a_rsp_ready(a_rsp_ready),
        .a_rdata(a_rdata), .a_error(a_error),
        .m_axi_awaddr(m_axi_awaddr), .m_axi_awprot(m_axi_awprot),
        .m_axi_awvalid(m_axi_awvalid), .m_axi_wdata(m_axi_wdata),
        .m_axi_wstrb(m_axi_wstrb), .m_axi_wvalid(m_axi_wvalid),
        .m_axi_bready(m_axi_bready), .m_axi_araddr(m_axi_araddr),
        .m_axi_arprot(m_axi_arprot), .m_axi_arvalid(m_axi_arvalid),
        .m_axi_rready(m_axi_rready), .m_axi_awready(m_axi_awready),
        .m_axi_wready(m_axi_wready), .m_axi_bresp(m_axi_bresp),
        .m_axi_bvalid(m_axi_bvalid), .m_axi_arready(m_axi_arready),
        .m_axi_rdata(m_axi_rdata), .m_axi_rresp(m_axi_rresp),
        .m_axi_rvalid(m_axi_rvalid)
    );
endmodule
