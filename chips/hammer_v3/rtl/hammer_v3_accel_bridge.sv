module hammer_v3_accel_bridge #(
    parameter integer DMEM_WORDS = 8192
) (
    input wire clk, rst_n, allow_transaction,
    output wire exclusive, quiesce_valid,
    input wire quiesce_ready, quiesce_error,
    output wire mem_req_valid, mem_req_write,
    input wire mem_req_ready,
    output wire [63:0] mem_req_addr, mem_req_wdata,
    output wire [7:0] mem_req_wstrb,
    input wire mem_rsp_valid,
    output wire mem_rsp_ready,
    input wire [63:0] mem_rsp_rdata,
    input wire mem_rsp_error, mem_rsp_decerr,
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
    localparam [3:0] IDLE=0, COLLECT=1, MAINTAIN=2, WRITE_LOAD=3,
        WRITE_SEND=4, WRITE_WAIT=5, READ_SEND=6, READ_WAIT=7,
        READ_RESPONSE=8, WRITE_RESPONSE=9;
    reg [3:0] state;
    reg prefer_write, owns_fabric, write_q, increment_q, read_invalid;
    reg [3:0] id_q;
    reg [63:0] base_q, addr_q, read_data_q;
    reg [7:0] len_q, beat_q;
    reg [2:0] size_q;
    reg [1:0] status_q;
    (* nomem2reg *) reg [63:0] write_data [0:15];
    (* nomem2reg *) reg [7:0] write_strobe [0:15];
    reg [63:0] write_data_q;
    reg [7:0] write_strobe_q;
    wire aw_geometry_error, aw_address_error, ar_geometry_error, ar_address_error;
    wire admit = rst_n && state == IDLE && allow_transaction;
    wire aw_accept = s_acc_axi_awvalid && s_acc_axi_awready;
    wire ar_accept = s_acc_axi_arvalid && s_acc_axi_arready;
    wire w_accept = s_acc_axi_wvalid && s_acc_axi_wready;
    reg [7:0] beat_mask;
    reg [63:0] read_mask;
    wire [63:0] step = 64'd1 << size_q;
    wire bad_write_beat = s_acc_axi_wlast != (beat_q == len_q) ||
        |(s_acc_axi_wstrb & ~beat_mask);
    wire [1:0] write_status = status_q != 0 ? status_q :
        bad_write_beat ? 2'b10 : 2'b00;
    integer n;

    hammer_v3_axi_geometry #(.DMEM_WORDS(DMEM_WORDS)) u_write_geometry (
        .addr(s_acc_axi_awaddr), .len(s_acc_axi_awlen), .size(s_acc_axi_awsize),
        .burst(s_acc_axi_awburst), .lock(s_acc_axi_awlock),
        .geometry_error(aw_geometry_error), .address_error(aw_address_error)
    );
    hammer_v3_axi_geometry #(.DMEM_WORDS(DMEM_WORDS)) u_read_geometry (
        .addr(s_acc_axi_araddr), .len(s_acc_axi_arlen), .size(s_acc_axi_arsize),
        .burst(s_acc_axi_arburst), .lock(s_acc_axi_arlock),
        .geometry_error(ar_geometry_error), .address_error(ar_address_error)
    );
    always @* begin
        case (size_q)
            3'd0: beat_mask = 8'h01 << addr_q[2:0];
            3'd1: beat_mask = 8'h03 << addr_q[2:0];
            3'd2: beat_mask = 8'h0f << addr_q[2:0];
            3'd3: beat_mask = 8'hff;
            default: beat_mask = 8'b0;
        endcase
        read_mask = 64'b0;
        for (n = 0; n < 8; n = n + 1)
            read_mask[n*8 +: 8] = {8{beat_mask[n]}};
    end

    assign s_acc_axi_awready = admit && (!s_acc_axi_arvalid || prefer_write);
    assign s_acc_axi_arready = admit && (!s_acc_axi_awvalid || !prefer_write);
    assign s_acc_axi_wready = rst_n && state == COLLECT;
    assign s_acc_axi_bvalid = rst_n && state == WRITE_RESPONSE;
    assign s_acc_axi_bid = s_acc_axi_bvalid ? id_q : 4'b0;
    assign s_acc_axi_bresp = s_acc_axi_bvalid ? status_q : 2'b0;
    assign s_acc_axi_rvalid = rst_n && state == READ_RESPONSE;
    assign s_acc_axi_rid = s_acc_axi_rvalid ? id_q : 4'b0;
    assign s_acc_axi_rdata = s_acc_axi_rvalid && status_q == 0 ? read_data_q : 64'b0;
    assign s_acc_axi_rresp = s_acc_axi_rvalid ? status_q : 2'b0;
    assign s_acc_axi_rlast = s_acc_axi_rvalid && beat_q == len_q;
    assign exclusive = rst_n && owns_fabric;
    assign quiesce_valid = rst_n && state == MAINTAIN;
    assign mem_req_valid = rst_n && (state == WRITE_SEND || state == READ_SEND);
    assign mem_req_write = mem_req_valid && state == WRITE_SEND;
    assign mem_req_addr = mem_req_valid ? {addr_q[63:3],3'b0} : 64'b0;
    assign mem_req_wdata = mem_req_write ? write_data_q : 64'b0;
    assign mem_req_wstrb = mem_req_write ? write_strobe_q : 8'b0;
    assign mem_rsp_ready = rst_n && (state == WRITE_WAIT || state == READ_WAIT);

    always @(posedge clk) begin
        if (rst_n && w_accept && beat_q < 16) begin
            write_data[beat_q[3:0]] <= s_acc_axi_wdata;
            write_strobe[beat_q[3:0]] <= s_acc_axi_wstrb;
        end
        if (rst_n && state == WRITE_LOAD) begin
            write_data_q <= write_data[beat_q[3:0]];
            write_strobe_q <= write_strobe[beat_q[3:0]];
        end
    end
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            prefer_write <= 1'b1;
            owns_fabric <= 1'b0;
            write_q <= 1'b0;
            increment_q <= 1'b0;
            read_invalid <= 1'b0;
            id_q <= 4'b0;
            base_q <= 64'b0;
            addr_q <= 64'b0;
            read_data_q <= 64'b0;
            len_q <= 8'b0;
            beat_q <= 8'b0;
            size_q <= 3'b0;
            status_q <= 2'b0;
        end else begin
            case (state)
                IDLE: begin
                    if (aw_accept) begin
                        prefer_write <= 1'b0;
                        write_q <= 1'b1;
                        id_q <= s_acc_axi_awid;
                        base_q <= s_acc_axi_awaddr;
                        addr_q <= s_acc_axi_awaddr;
                        len_q <= s_acc_axi_awlen;
                        beat_q <= 8'b0;
                        size_q <= s_acc_axi_awsize;
                        increment_q <= s_acc_axi_awburst == 1;
                        status_q <= aw_geometry_error ? 2'b10 :
                            aw_address_error ? 2'b11 : 2'b00;
                        state <= COLLECT;
                    end else if (ar_accept) begin
                        prefer_write <= 1'b1;
                        write_q <= 1'b0;
                        id_q <= s_acc_axi_arid;
                        base_q <= s_acc_axi_araddr;
                        addr_q <= s_acc_axi_araddr;
                        len_q <= s_acc_axi_arlen;
                        beat_q <= 8'b0;
                        size_q <= s_acc_axi_arsize;
                        increment_q <= s_acc_axi_arburst == 1;
                        status_q <= ar_geometry_error ? 2'b10 :
                            ar_address_error ? 2'b11 : 2'b00;
                        read_data_q <= 64'b0;
                        read_invalid <= ar_geometry_error || ar_address_error;
                        if (ar_geometry_error || ar_address_error)
                            state <= READ_RESPONSE;
                        else begin
                            owns_fabric <= 1'b1;
                            state <= MAINTAIN;
                        end
                    end
                end
                COLLECT: if (w_accept) begin
                    status_q <= write_status;
                    if (beat_q == len_q) begin
                        beat_q <= 8'b0;
                        addr_q <= base_q;
                        if (write_status != 0) state <= WRITE_RESPONSE;
                        else begin
                            owns_fabric <= 1'b1;
                            state <= MAINTAIN;
                        end
                    end else begin
                        beat_q <= beat_q + 1'b1;
                        if (increment_q) addr_q <= addr_q + step;
                    end
                end
                MAINTAIN: if (quiesce_ready) begin
                    if (quiesce_error) begin
                        status_q <= 2'b10;
                        read_invalid <= 1'b1;
                        read_data_q <= 64'b0;
                        if (write_q) state <= WRITE_RESPONSE;
                        else state <= READ_RESPONSE;
                    end else if (write_q) state <= WRITE_LOAD;
                    else state <= READ_SEND;
                end
                WRITE_LOAD: state <= WRITE_SEND;
                WRITE_SEND: if (mem_req_ready) state <= WRITE_WAIT;
                WRITE_WAIT: if (mem_rsp_valid) begin
                    if (mem_rsp_error) begin
                        status_q <= mem_rsp_decerr ? 2'b11 : 2'b10;
                        state <= WRITE_RESPONSE;
                    end else if (beat_q == len_q) state <= WRITE_RESPONSE;
                    else begin
                        beat_q <= beat_q + 1'b1;
                        if (increment_q) addr_q <= addr_q + step;
                        state <= WRITE_LOAD;
                    end
                end
                READ_SEND: if (mem_req_ready) state <= READ_WAIT;
                READ_WAIT: if (mem_rsp_valid) begin
                    read_data_q <= mem_rsp_rdata & read_mask;
                    status_q <= mem_rsp_error ? (mem_rsp_decerr ? 2'b11 : 2'b10) : 2'b00;
                    state <= READ_RESPONSE;
                end
                READ_RESPONSE: if (s_acc_axi_rready) begin
                    if (beat_q == len_q) begin
                        owns_fabric <= 1'b0;
                        state <= IDLE;
                    end else begin
                        beat_q <= beat_q + 1'b1;
                        if (increment_q) addr_q <= addr_q + step;
                        if (!read_invalid) state <= READ_SEND;
                    end
                end
                WRITE_RESPONSE: if (s_acc_axi_bready) begin
                    owns_fabric <= 1'b0;
                    state <= IDLE;
                end
                default: state <= IDLE;
            endcase
        end
    end
endmodule
