module hammer_v3_axi_master (
    input wire clk, rst_n,
    input wire req_valid, req_write,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    input wire [2:0] req_prot,
    output wire req_ready,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error, rsp_decerr,
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
    output wire m_mem_axi_rready
);
    localparam [2:0] IDLE=0, WRITE=1, WAIT_B=2, READ=3, WAIT_R=4, RESPONSE=5;
    reg [2:0] state;
    reg [63:0] addr_q, wdata_q, rdata_q;
    reg [7:0] strb_q;
    reg [2:0] prot_q;
    reg aw_done, w_done, error_q, decerr_q;
    wire aw_accept = m_mem_axi_awvalid && m_mem_axi_awready;
    wire w_accept = m_mem_axi_wvalid && m_mem_axi_wready;
    wire request_bad = |req_addr[2:0] || req_addr < 64'h80000000 ||
        req_addr >= 64'h100000000;
    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_rdata = rsp_valid && !error_q ? rdata_q : 64'b0;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_decerr = rsp_valid && decerr_q;
    assign m_mem_axi_awid = 4'b0;
    assign m_mem_axi_awlen = 8'b0;
    assign m_mem_axi_awsize = 3'd3;
    assign m_mem_axi_awburst = 2'd1;
    assign m_mem_axi_awlock = 1'b0;
    assign m_mem_axi_awcache = 4'hf;
    assign m_mem_axi_awqos = 4'b0;
    assign m_mem_axi_awvalid = rst_n && state == WRITE && !aw_done;
    assign m_mem_axi_awaddr = m_mem_axi_awvalid ? addr_q : 64'b0;
    assign m_mem_axi_awprot = m_mem_axi_awvalid ? prot_q : 3'b0;
    assign m_mem_axi_wvalid = rst_n && state == WRITE && !w_done;
    assign m_mem_axi_wdata = m_mem_axi_wvalid ? wdata_q : 64'b0;
    assign m_mem_axi_wstrb = m_mem_axi_wvalid ? strb_q : 8'b0;
    assign m_mem_axi_wlast = 1'b1;
    assign m_mem_axi_bready = rst_n && state == WAIT_B;
    assign m_mem_axi_arid = 4'b0;
    assign m_mem_axi_arlen = 8'b0;
    assign m_mem_axi_arsize = 3'd3;
    assign m_mem_axi_arburst = 2'd1;
    assign m_mem_axi_arlock = 1'b0;
    assign m_mem_axi_arcache = 4'hf;
    assign m_mem_axi_arqos = 4'b0;
    assign m_mem_axi_arvalid = rst_n && state == READ;
    assign m_mem_axi_araddr = m_mem_axi_arvalid ? addr_q : 64'b0;
    assign m_mem_axi_arprot = m_mem_axi_arvalid ? prot_q : 3'b0;
    assign m_mem_axi_rready = rst_n && state == WAIT_R;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            addr_q <= 64'b0;
            wdata_q <= 64'b0;
            rdata_q <= 64'b0;
            strb_q <= 8'b0;
            prot_q <= 3'b0;
            aw_done <= 1'b0;
            w_done <= 1'b0;
            error_q <= 1'b0;
            decerr_q <= 1'b0;
        end else begin
            case (state)
                IDLE: if (req_valid && req_ready) begin
                    addr_q <= req_addr;
                    wdata_q <= req_wdata;
                    strb_q <= req_wstrb;
                    prot_q <= req_prot;
                    aw_done <= 1'b0;
                    w_done <= 1'b0;
                    rdata_q <= 64'b0;
                    error_q <= request_bad;
                    decerr_q <= request_bad;
                    if (request_bad) state <= RESPONSE;
                    else if (req_write) state <= WRITE;
                    else state <= READ;
                end
                WRITE: begin
                    if (aw_accept) aw_done <= 1'b1;
                    if (w_accept) w_done <= 1'b1;
                    if ((aw_done || aw_accept) && (w_done || w_accept))
                        state <= WAIT_B;
                end
                WAIT_B: if (m_mem_axi_bvalid) begin
                    error_q <= m_mem_axi_bresp != 0 || m_mem_axi_bid != 0;
                    decerr_q <= m_mem_axi_bresp == 3;
                    state <= RESPONSE;
                end
                READ: if (m_mem_axi_arready) state <= WAIT_R;
                WAIT_R: if (m_mem_axi_rvalid) begin
                    rdata_q <= m_mem_axi_rdata;
                    error_q <= m_mem_axi_rresp != 0 || m_mem_axi_rid != 0 ||
                        !m_mem_axi_rlast;
                    decerr_q <= m_mem_axi_rresp == 3;
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
