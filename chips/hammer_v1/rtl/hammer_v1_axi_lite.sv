module hammer_v1_axi_lite (
    input wire clk, rst_n,
    input wire a_valid,
    output wire a_ready,
    input wire a_write,
    input wire [31:0] a_addr,
    input wire [63:0] a_wdata,
    input wire [7:0] a_wstrb,
    output wire a_rsp_valid,
    input wire a_rsp_ready,
    output wire [63:0] a_rdata,
    output wire a_error,
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
    reg active, write_q, aw_pending, w_pending, ar_pending, response;
    reg [31:0] addr_q;
    reg [63:0] data_q, read_q;
    reg [7:0] strb_q;
    reg error_q;
    assign a_ready = rst_n && !active && !response;
    assign a_rsp_valid = rst_n && response;
    assign a_rdata = rst_n && response ? read_q : 64'b0;
    assign a_error = rst_n && response && error_q;
    assign m_axi_awvalid = rst_n && active && write_q && aw_pending;
    assign m_axi_wvalid = rst_n && active && write_q && w_pending;
    assign m_axi_arvalid = rst_n && active && !write_q && ar_pending;
    assign m_axi_bready = rst_n && active && write_q &&
                          !aw_pending && !w_pending && !response;
    assign m_axi_rready = rst_n && active && !write_q &&
                          !ar_pending && !response;
    assign m_axi_awaddr = rst_n && active && write_q ? addr_q : 32'b0;
    assign m_axi_araddr = rst_n && active && !write_q ? addr_q : 32'b0;
    assign m_axi_awprot = 3'b0;
    assign m_axi_arprot = 3'b0;
    assign m_axi_wdata = rst_n && active && write_q ? data_q : 64'b0;
    assign m_axi_wstrb = rst_n && active && write_q ? strb_q : 8'b0;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            active <= 1'b0;
            write_q <= 1'b0;
            aw_pending <= 1'b0;
            w_pending <= 1'b0;
            ar_pending <= 1'b0;
            response <= 1'b0;
            addr_q <= 32'b0;
            data_q <= 64'b0;
            strb_q <= 8'b0;
            read_q <= 64'b0;
            error_q <= 1'b0;
        end else begin
            if (a_valid && a_ready) begin
                active <= 1'b1;
                write_q <= a_write;
                addr_q <= a_addr;
                data_q <= a_wdata;
                strb_q <= a_wstrb;
                aw_pending <= a_write;
                w_pending <= a_write;
                ar_pending <= !a_write;
                read_q <= 64'b0;
                error_q <= 1'b0;
            end
            if (m_axi_awvalid && m_axi_awready) aw_pending <= 1'b0;
            if (m_axi_wvalid && m_axi_wready) w_pending <= 1'b0;
            if (m_axi_arvalid && m_axi_arready) ar_pending <= 1'b0;
            if (m_axi_bvalid && m_axi_bready) begin
                response <= 1'b1;
                error_q <= m_axi_bresp != 2'b00;
            end
            if (m_axi_rvalid && m_axi_rready) begin
                response <= 1'b1;
                read_q <= m_axi_rdata;
                error_q <= m_axi_rresp != 2'b00;
            end
            if (a_rsp_valid && a_rsp_ready) begin
                active <= 1'b0;
                response <= 1'b0;
            end
        end
    end
endmodule
