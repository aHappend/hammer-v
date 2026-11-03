module hammer_v3_ptw (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_va,
    input wire [43:0] req_root_ppn,
    input wire [15:0] req_asid,
    input wire [1:0] req_access, req_priv,
    input wire req_sum, req_mxr,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [55:0] rsp_pa,
    output wire rsp_page_fault, rsp_access_fault,
    output wire [43:0] rsp_ppn,
    output wire [1:0] rsp_level,
    output wire [7:0] rsp_flags,
    output wire [63:0] rsp_va,
    output wire [15:0] rsp_asid,
    output wire mem_req_valid,
    input wire mem_req_ready,
    output wire [55:0] mem_req_addr,
    input wire mem_rsp_valid,
    output wire mem_rsp_ready,
    input wire [63:0] mem_rsp_rdata,
    input wire mem_rsp_error
);
    localparam [2:0] IDLE=0, ADDRESS=1, REQUEST=2, WAIT_PTE=3,
        CLASSIFY=4, FINALIZE=5, RESPONSE=6;
    reg [2:0] state;
    reg [63:0] va_q, pte_q;
    reg [43:0] table_ppn, result_ppn;
    reg [15:0] asid_q;
    reg [1:0] access_q, priv_q, level_q;
    reg sum_q, mxr_q, global_q, bus_error_q;
    reg [55:0] pte_addr, result_pa;
    reg [7:0] result_flags;
    reg page_fault_q, access_fault_q;
    reg [8:0] vpn_index;
    wire [7:0] leaf_flags = pte_q[7:0] | {2'b0,global_q,5'b0};
    wire [55:0] leaf_pa;
    wire leaf_fault;
    wire pte_invalid = !pte_q[0] || (!pte_q[1] && pte_q[2]) ||
        |pte_q[63:54];
    wire pte_leaf = pte_q[1] || pte_q[3];
    wire nonleaf_invalid = pte_q[4] || pte_q[6] || pte_q[7] || level_q == 0;

    always @* begin
        case (level_q)
            2'd2: vpn_index = va_q[38:30];
            2'd1: vpn_index = va_q[29:21];
            default: vpn_index = va_q[20:12];
        endcase
    end
    hammer_v3_page_leaf u_permissions (
        .va(va_q), .ppn(pte_q[53:10]), .level(level_q), .flags(leaf_flags),
        .access_kind(access_q), .priv(priv_q), .sum(sum_q), .mxr(mxr_q),
        .pa(leaf_pa), .fault(leaf_fault)
    );
    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_pa = rsp_valid && !page_fault_q && !access_fault_q ?
        result_pa : 56'b0;
    assign rsp_page_fault = rsp_valid && page_fault_q;
    assign rsp_access_fault = rsp_valid && access_fault_q;
    assign rsp_ppn = rsp_valid && !page_fault_q && !access_fault_q ?
        result_ppn : 44'b0;
    assign rsp_level = rsp_valid ? level_q : 2'b0;
    assign rsp_flags = rsp_valid && !page_fault_q && !access_fault_q ?
        result_flags : 8'b0;
    assign rsp_va = rsp_valid ? va_q : 64'b0;
    assign rsp_asid = rsp_valid ? asid_q : 16'b0;
    assign mem_req_valid = rst_n && state == REQUEST;
    assign mem_req_addr = mem_req_valid ? pte_addr : 56'b0;
    assign mem_rsp_ready = rst_n && state == WAIT_PTE;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            va_q <= 64'b0;
            pte_q <= 64'b0;
            table_ppn <= 44'b0;
            result_ppn <= 44'b0;
            asid_q <= 16'b0;
            access_q <= 2'b0;
            priv_q <= 2'b0;
            level_q <= 2'b0;
            sum_q <= 1'b0;
            mxr_q <= 1'b0;
            global_q <= 1'b0;
            bus_error_q <= 1'b0;
            pte_addr <= 56'b0;
            result_pa <= 56'b0;
            result_flags <= 8'b0;
            page_fault_q <= 1'b0;
            access_fault_q <= 1'b0;
        end else begin
            case (state)
                IDLE: if (req_valid && req_ready) begin
                    va_q <= req_va;
                    table_ppn <= req_root_ppn;
                    asid_q <= req_asid;
                    access_q <= req_access;
                    priv_q <= req_priv;
                    sum_q <= req_sum;
                    mxr_q <= req_mxr;
                    level_q <= 2'd2;
                    global_q <= 1'b0;
                    bus_error_q <= 1'b0;
                    page_fault_q <= 1'b0;
                    access_fault_q <= 1'b0;
                    result_ppn <= 44'b0;
                    result_pa <= 56'b0;
                    result_flags <= 8'b0;
                    if (req_va[63:39] != {25{req_va[38]}}) begin
                        page_fault_q <= 1'b1;
                        state <= FINALIZE;
                    end else state <= ADDRESS;
                end
                ADDRESS: begin
                    pte_addr <= {table_ppn,12'b0} + {44'b0,vpn_index,3'b0};
                    state <= REQUEST;
                end
                REQUEST: if (mem_req_ready) state <= WAIT_PTE;
                WAIT_PTE: if (mem_rsp_valid) begin
                    pte_q <= mem_rsp_rdata;
                    bus_error_q <= mem_rsp_error;
                    state <= CLASSIFY;
                end
                CLASSIFY: begin
                    if (bus_error_q) begin
                        access_fault_q <= 1'b1;
                        state <= FINALIZE;
                    end else if (pte_invalid) begin
                        page_fault_q <= 1'b1;
                        state <= FINALIZE;
                    end else if (pte_leaf) begin
                        page_fault_q <= leaf_fault;
                        result_pa <= leaf_pa;
                        result_ppn <= pte_q[53:10];
                        result_flags <= leaf_flags;
                        state <= FINALIZE;
                    end else if (nonleaf_invalid) begin
                        page_fault_q <= 1'b1;
                        state <= FINALIZE;
                    end else begin
                        global_q <= global_q || pte_q[5];
                        table_ppn <= pte_q[53:10];
                        level_q <= level_q - 1'b1;
                        state <= ADDRESS;
                    end
                end
                FINALIZE: state <= RESPONSE;
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
