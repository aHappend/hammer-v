module hammer_v3_mmu #(
    parameter integer ITLB_ENTRIES = 8,
    parameter integer DTLB_ENTRIES = 8
) (
    input wire clk, rst_n,
    input wire [63:0] satp, mstatus,
    input wire [1:0] priv,
    input wire i_req_valid,
    output wire i_req_ready,
    input wire [63:0] i_req_va,
    input wire i_req_bypass,
    output wire i_rsp_valid,
    input wire i_rsp_ready,
    output wire [55:0] i_rsp_pa,
    output wire i_rsp_page_fault, i_rsp_access_fault,
    input wire d_req_valid,
    output wire d_req_ready,
    input wire [63:0] d_req_va,
    input wire [1:0] d_req_access,
    input wire d_req_bypass,
    output wire d_rsp_valid,
    input wire d_rsp_ready,
    output wire [55:0] d_rsp_pa,
    output wire d_rsp_page_fault, d_rsp_access_fault,
    input wire sfence_valid,
    output wire sfence_ready,
    input wire sfence_va_valid, sfence_asid_valid,
    input wire [63:0] sfence_va,
    input wire [15:0] sfence_asid,
    output wire pt_req_valid,
    input wire pt_req_ready,
    output wire [55:0] pt_req_addr,
    input wire pt_rsp_valid,
    output wire pt_rsp_ready,
    input wire [63:0] pt_rsp_rdata,
    input wire pt_rsp_error
);
    localparam [2:0] IDLE=0, LOOKUP=1, MISS=2, WALK=3, RESPONSE=4;
    localparam [1:0] NORMAL=0, DRAIN=1, INVALIDATE=2, ACK=3;
    reg [2:0] i_state, d_state;
    reg [1:0] fence_state;
    reg [63:0] satp_q;
    reg fence_explicit, fence_full, fence_va_valid, fence_asid_valid;
    reg [63:0] fence_va;
    reg [15:0] fence_asid;
    reg [63:0] i_va, d_va;
    reg [43:0] i_root, d_root;
    reg [15:0] i_asid, d_asid;
    reg [1:0] i_priv, d_priv, d_access;
    reg i_sum, i_mxr, d_sum, d_mxr, i_bypass, d_bypass;
    reg [55:0] i_pa, d_pa;
    reg i_page_fault, i_access_fault, d_page_fault, d_access_fault;
    reg walker_busy, walker_owner, prefer_data;
    wire [1:0] data_priv = priv == 3 && mstatus[17] ? mstatus[12:11] : priv;
    wire admit = rst_n && fence_state == NORMAL &&
        !sfence_valid && satp == satp_q;
    wire invalidate = rst_n && fence_state == INVALIDATE;
    wire invalidate_all = fence_full || satp != satp_q;
    wire it_ready, it_valid, it_hit, it_fault;
    wire dt_ready, dt_valid, dt_hit, dt_fault;
    wire [55:0] it_pa, dt_pa;
    wire walk_ready, walk_valid;
    wire [55:0] walk_pa;
    wire walk_page_fault, walk_access_fault;
    wire [43:0] walk_ppn;
    wire [1:0] walk_level;
    wire [7:0] walk_flags;
    wire [63:0] walk_va;
    wire [15:0] walk_asid;
    wire have_i_miss = i_state == MISS;
    wire have_d_miss = d_state == MISS;
    wire select_data = have_d_miss && (!have_i_miss || prefer_data);
    wire walk_request = rst_n && !walker_busy && (have_i_miss || have_d_miss);
    wire walk_accept = walk_request && walk_ready;
    wire walk_consume = rst_n && walker_busy &&
        (walker_owner ? d_state == WALK : i_state == WALK);
    wire walk_done = walk_consume && walk_valid;
    wire refill_i = walk_done && !walker_owner &&
        !walk_page_fault && !walk_access_fault;
    wire refill_d = walk_done && walker_owner &&
        !walk_page_fault && !walk_access_fault;
    wire drained = i_state == IDLE && d_state == IDLE &&
        !walker_busy && walk_ready;

    assign i_req_ready = admit && i_state == IDLE && it_ready;
    assign d_req_ready = admit && d_state == IDLE && dt_ready;
    assign i_rsp_valid = rst_n && i_state == RESPONSE;
    assign d_rsp_valid = rst_n && d_state == RESPONSE;
    assign i_rsp_pa = i_rsp_valid && !i_page_fault && !i_access_fault ? i_pa : 56'b0;
    assign d_rsp_pa = d_rsp_valid && !d_page_fault && !d_access_fault ? d_pa : 56'b0;
    assign i_rsp_page_fault = i_rsp_valid && i_page_fault;
    assign d_rsp_page_fault = d_rsp_valid && d_page_fault;
    assign i_rsp_access_fault = i_rsp_valid && i_access_fault;
    assign d_rsp_access_fault = d_rsp_valid && d_access_fault;
    assign sfence_ready = rst_n && fence_state == ACK && fence_explicit;

    hammer_v3_tlb #(.ENTRIES(ITLB_ENTRIES)) u_itlb (
        .clk(clk), .rst_n(rst_n), .req_valid(i_req_valid && i_req_ready),
        .req_ready(it_ready), .req_va(i_req_va), .req_asid(satp[59:44]),
        .req_access(2'd0), .req_priv(priv), .req_sum(mstatus[18]),
        .req_mxr(mstatus[19]), .rsp_valid(it_valid),
        .rsp_ready(rst_n && i_state == LOOKUP), .rsp_hit(it_hit),
        .rsp_pa(it_pa), .rsp_fault(it_fault),
        .refill_valid(refill_i), .refill_va(walk_va),
        .refill_asid(walk_asid), .refill_ppn(walk_ppn),
        .refill_level(walk_level), .refill_flags(walk_flags),
        .invalidate_valid(invalidate),
        .invalidate_va_valid(fence_va_valid && !invalidate_all),
        .invalidate_asid_valid(fence_asid_valid && !invalidate_all),
        .invalidate_va(fence_va), .invalidate_asid(fence_asid)
    );
    hammer_v3_tlb #(.ENTRIES(DTLB_ENTRIES)) u_dtlb (
        .clk(clk), .rst_n(rst_n), .req_valid(d_req_valid && d_req_ready),
        .req_ready(dt_ready), .req_va(d_req_va), .req_asid(satp[59:44]),
        .req_access(d_req_access), .req_priv(data_priv), .req_sum(mstatus[18]),
        .req_mxr(mstatus[19]), .rsp_valid(dt_valid),
        .rsp_ready(rst_n && d_state == LOOKUP), .rsp_hit(dt_hit),
        .rsp_pa(dt_pa), .rsp_fault(dt_fault),
        .refill_valid(refill_d), .refill_va(walk_va),
        .refill_asid(walk_asid), .refill_ppn(walk_ppn),
        .refill_level(walk_level), .refill_flags(walk_flags),
        .invalidate_valid(invalidate),
        .invalidate_va_valid(fence_va_valid && !invalidate_all),
        .invalidate_asid_valid(fence_asid_valid && !invalidate_all),
        .invalidate_va(fence_va), .invalidate_asid(fence_asid)
    );
    hammer_v3_ptw u_ptw (
        .clk(clk), .rst_n(rst_n), .req_valid(walk_request), .req_ready(walk_ready),
        .req_va(select_data ? d_va : i_va),
        .req_root_ppn(select_data ? d_root : i_root),
        .req_asid(select_data ? d_asid : i_asid),
        .req_access(select_data ? d_access : 2'd0),
        .req_priv(select_data ? d_priv : i_priv),
        .req_sum(select_data ? d_sum : i_sum),
        .req_mxr(select_data ? d_mxr : i_mxr),
        .rsp_valid(walk_valid), .rsp_ready(walk_consume), .rsp_pa(walk_pa),
        .rsp_page_fault(walk_page_fault), .rsp_access_fault(walk_access_fault),
        .rsp_ppn(walk_ppn), .rsp_level(walk_level), .rsp_flags(walk_flags),
        .rsp_va(walk_va), .rsp_asid(walk_asid),
        .mem_req_valid(pt_req_valid), .mem_req_ready(pt_req_ready),
        .mem_req_addr(pt_req_addr), .mem_rsp_valid(pt_rsp_valid),
        .mem_rsp_ready(pt_rsp_ready), .mem_rsp_rdata(pt_rsp_rdata),
        .mem_rsp_error(pt_rsp_error)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            i_state <= IDLE;
            d_state <= IDLE;
            fence_state <= NORMAL;
            satp_q <= 64'b0;
            fence_explicit <= 1'b0;
            fence_full <= 1'b0;
            fence_va_valid <= 1'b0;
            fence_asid_valid <= 1'b0;
            fence_va <= 64'b0;
            fence_asid <= 16'b0;
            i_va <= 64'b0;
            d_va <= 64'b0;
            i_root <= 44'b0;
            d_root <= 44'b0;
            i_asid <= 16'b0;
            d_asid <= 16'b0;
            i_priv <= 2'b0;
            d_priv <= 2'b0;
            d_access <= 2'b0;
            i_sum <= 1'b0;
            i_mxr <= 1'b0;
            d_sum <= 1'b0;
            d_mxr <= 1'b0;
            i_bypass <= 1'b0;
            d_bypass <= 1'b0;
            i_pa <= 56'b0;
            d_pa <= 56'b0;
            i_page_fault <= 1'b0;
            i_access_fault <= 1'b0;
            d_page_fault <= 1'b0;
            d_access_fault <= 1'b0;
            walker_busy <= 1'b0;
            walker_owner <= 1'b0;
            prefer_data <= 1'b0;
        end else begin
            case (fence_state)
                NORMAL: if (sfence_valid || satp != satp_q) begin
                    fence_explicit <= sfence_valid;
                    fence_full <= satp != satp_q;
                    fence_va_valid <= sfence_valid && sfence_va_valid;
                    fence_asid_valid <= sfence_valid && sfence_asid_valid;
                    fence_va <= sfence_valid ? sfence_va : 64'b0;
                    fence_asid <= sfence_valid ? sfence_asid : 16'b0;
                    fence_state <= DRAIN;
                end
                DRAIN: begin
                    if (satp != satp_q) fence_full <= 1'b1;
                    if (!fence_explicit && sfence_valid) begin
                        fence_explicit <= 1'b1;
                        fence_va_valid <= sfence_va_valid;
                        fence_asid_valid <= sfence_asid_valid;
                        fence_va <= sfence_va;
                        fence_asid <= sfence_asid;
                    end
                    if (drained) fence_state <= INVALIDATE;
                end
                INVALIDATE: begin
                    satp_q <= satp;
                    fence_state <= ACK;
                end
                ACK: if (!fence_explicit || sfence_valid) begin
                    fence_explicit <= 1'b0;
                    fence_state <= NORMAL;
                end
                default: fence_state <= NORMAL;
            endcase
            case (i_state)
                IDLE: if (i_req_valid && i_req_ready) begin
                    i_va <= i_req_va;
                    i_root <= satp[43:0];
                    i_asid <= satp[59:44];
                    i_priv <= priv;
                    i_sum <= mstatus[18];
                    i_mxr <= mstatus[19];
                    i_bypass <= i_req_bypass || priv == 3 || satp[63:60] == 0;
                    i_page_fault <= 1'b0;
                    i_access_fault <= 1'b0;
                    i_pa <= 56'b0;
                    i_state <= LOOKUP;
                end
                LOOKUP: if (it_valid) begin
                    if (i_bypass) begin
                        i_pa <= i_va[55:0];
                        i_access_fault <= |i_va[63:56];
                        i_state <= RESPONSE;
                    end else if (i_va[63:39] != {25{i_va[38]}}) begin
                        i_page_fault <= 1'b1;
                        i_state <= RESPONSE;
                    end else if (it_hit) begin
                        i_pa <= it_pa;
                        i_page_fault <= it_fault;
                        i_state <= RESPONSE;
                    end else i_state <= MISS;
                end
                MISS: if (walk_accept && !select_data) i_state <= WALK;
                WALK: if (walk_done && !walker_owner) begin
                    i_pa <= walk_pa;
                    i_page_fault <= walk_page_fault;
                    i_access_fault <= walk_access_fault;
                    i_state <= RESPONSE;
                end
                RESPONSE: if (i_rsp_ready) i_state <= IDLE;
                default: i_state <= IDLE;
            endcase
            case (d_state)
                IDLE: if (d_req_valid && d_req_ready) begin
                    d_va <= d_req_va;
                    d_root <= satp[43:0];
                    d_asid <= satp[59:44];
                    d_priv <= data_priv;
                    d_access <= d_req_access;
                    d_sum <= mstatus[18];
                    d_mxr <= mstatus[19];
                    d_bypass <= d_req_bypass || data_priv == 3 || satp[63:60] == 0;
                    d_page_fault <= 1'b0;
                    d_access_fault <= 1'b0;
                    d_pa <= 56'b0;
                    d_state <= LOOKUP;
                end
                LOOKUP: if (dt_valid) begin
                    if (d_bypass) begin
                        d_pa <= d_va[55:0];
                        d_access_fault <= |d_va[63:56];
                        d_state <= RESPONSE;
                    end else if (d_va[63:39] != {25{d_va[38]}}) begin
                        d_page_fault <= 1'b1;
                        d_state <= RESPONSE;
                    end else if (dt_hit) begin
                        d_pa <= dt_pa;
                        d_page_fault <= dt_fault;
                        d_state <= RESPONSE;
                    end else d_state <= MISS;
                end
                MISS: if (walk_accept && select_data) d_state <= WALK;
                WALK: if (walk_done && walker_owner) begin
                    d_pa <= walk_pa;
                    d_page_fault <= walk_page_fault;
                    d_access_fault <= walk_access_fault;
                    d_state <= RESPONSE;
                end
                RESPONSE: if (d_rsp_ready) d_state <= IDLE;
                default: d_state <= IDLE;
            endcase
            if (walk_accept) begin
                walker_busy <= 1'b1;
                walker_owner <= select_data;
                prefer_data <= !select_data;
            end
            if (walk_done) walker_busy <= 1'b0;
        end
    end
endmodule
