module hammer_v3_tlb #(
    parameter integer ENTRIES = 8
) (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_va,
    input wire [15:0] req_asid,
    input wire [1:0] req_access, req_priv,
    input wire req_sum, req_mxr,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire rsp_hit,
    output wire [55:0] rsp_pa,
    output wire rsp_fault,
    input wire refill_valid,
    input wire [63:0] refill_va,
    input wire [15:0] refill_asid,
    input wire [43:0] refill_ppn,
    input wire [1:0] refill_level,
    input wire [7:0] refill_flags,
    input wire invalidate_valid, invalidate_va_valid, invalidate_asid_valid,
    input wire [63:0] invalidate_va,
    input wire [15:0] invalidate_asid
);
    localparam integer LEGAL = ENTRIES == 1 || ENTRIES == 4 ||
        ENTRIES == 8 || ENTRIES == 16;
    initial begin
        if (!LEGAL)
            $fatal(1, "PARAMETER ERROR: TLB ENTRIES must be 1,4,8,16");
    end
    generate if (LEGAL) begin : g_legal
        localparam integer IW = ENTRIES == 1 ? 1 : $clog2(ENTRIES);
        localparam [1:0] IDLE=0, LOOKUP=1, RESPONSE=2;
        reg [1:0] state;
        reg [ENTRIES-1:0] valid;
        reg [63:0] va [0:ENTRIES-1];
        reg [43:0] ppn [0:ENTRIES-1];
        reg [15:0] asid [0:ENTRIES-1];
        reg [1:0] level [0:ENTRIES-1];
        reg [7:0] flags [0:ENTRIES-1];
        reg [IW-1:0] replacement;
        reg [63:0] va_q;
        reg [15:0] asid_q;
        reg [1:0] access_q, priv_q;
        reg sum_q, mxr_q, hit_q, fault_q;
        reg [55:0] pa_q;
        reg found;
        reg [43:0] hit_ppn;
        reg [1:0] hit_level;
        reg [7:0] hit_flags;
        reg [IW-1:0] refill_slot;
        reg slot_found;
        wire [55:0] leaf_pa;
        wire leaf_fault;
        integer k, n;

        function automatic same_page (
            input [63:0] a, b,
            input [1:0] page_level
        );
            begin
                case (page_level)
                    2'd2: same_page = a[38:30] == b[38:30];
                    2'd1: same_page = a[38:21] == b[38:21];
                    default: same_page = a[38:12] == b[38:12];
                endcase
            end
        endfunction

        always @* begin
            found = 1'b0;
            hit_ppn = 44'b0;
            hit_level = 2'b0;
            hit_flags = 8'b0;
            refill_slot = replacement;
            slot_found = 1'b0;
            for (k = 0; k < ENTRIES; k = k + 1) begin
                if (!found && valid[k] &&
                    (flags[k][5] || asid[k] == asid_q) &&
                    same_page(va[k],va_q,level[k])) begin
                    found = 1'b1;
                    hit_ppn = ppn[k];
                    hit_level = level[k];
                    hit_flags = flags[k];
                end
                if (!slot_found && !valid[k]) begin
                    refill_slot = k;
                    slot_found = 1'b1;
                end
            end
        end
        hammer_v3_page_leaf u_permissions (
            .va(va_q), .ppn(hit_ppn), .level(hit_level), .flags(hit_flags),
            .access_kind(access_q), .priv(priv_q), .sum(sum_q), .mxr(mxr_q),
            .pa(leaf_pa), .fault(leaf_fault)
        );
        assign req_ready = rst_n && state == IDLE && !invalidate_valid;
        assign rsp_valid = rst_n && state == RESPONSE;
        assign rsp_hit = rsp_valid && hit_q;
        assign rsp_pa = rsp_hit && !fault_q ? pa_q : 56'b0;
        assign rsp_fault = rsp_hit && fault_q;

        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                state <= IDLE;
                valid <= {ENTRIES{1'b0}};
                replacement <= {IW{1'b0}};
                va_q <= 64'b0;
                asid_q <= 16'b0;
                access_q <= 2'b0;
                priv_q <= 2'b0;
                sum_q <= 1'b0;
                mxr_q <= 1'b0;
                hit_q <= 1'b0;
                fault_q <= 1'b0;
                pa_q <= 56'b0;
                for (n = 0; n < ENTRIES; n = n + 1) begin
                    va[n] <= 64'b0;
                    ppn[n] <= 44'b0;
                    asid[n] <= 16'b0;
                    level[n] <= 2'b0;
                    flags[n] <= 8'b0;
                end
            end else begin
                case (state)
                    IDLE: if (req_valid && req_ready) begin
                        va_q <= req_va;
                        asid_q <= req_asid;
                        access_q <= req_access;
                        priv_q <= req_priv;
                        sum_q <= req_sum;
                        mxr_q <= req_mxr;
                        state <= LOOKUP;
                    end
                    LOOKUP: begin
                        hit_q <= found;
                        fault_q <= found && leaf_fault;
                        pa_q <= found && !leaf_fault ? leaf_pa : 56'b0;
                        state <= RESPONSE;
                    end
                    RESPONSE: if (rsp_ready) state <= IDLE;
                    default: state <= IDLE;
                endcase
                if (invalidate_valid) begin
                    replacement <= {IW{1'b0}};
                    for (n = 0; n < ENTRIES; n = n + 1)
                        if (valid[n] &&
                            (!invalidate_va_valid ||
                             same_page(va[n],invalidate_va,level[n])) &&
                            (!invalidate_asid_valid ||
                             (!flags[n][5] && asid[n] == invalidate_asid)))
                            valid[n] <= 1'b0;
                end else if (refill_valid) begin
                    for (n = 0; n < ENTRIES; n = n + 1)
                        if (valid[n] &&
                            (flags[n][5] || refill_flags[5] ||
                             asid[n] == refill_asid) &&
                            (same_page(va[n],refill_va,level[n]) ||
                             same_page(va[n],refill_va,refill_level)))
                            valid[n] <= 1'b0;
                    valid[refill_slot] <= 1'b1;
                    va[refill_slot] <= refill_va;
                    ppn[refill_slot] <= refill_ppn;
                    asid[refill_slot] <= refill_asid;
                    level[refill_slot] <= refill_level;
                    flags[refill_slot] <= refill_flags;
                    if (refill_slot == ENTRIES-1)
                        replacement <= {IW{1'b0}};
                    else replacement <= refill_slot + 1'b1;
                end
            end
        end
    end else begin : g_bad
        assign req_ready = 1'b0;
        assign rsp_valid = 1'b0;
        assign rsp_hit = 1'b0;
        assign rsp_pa = 56'b0;
        assign rsp_fault = 1'b0;
    end endgenerate
endmodule
