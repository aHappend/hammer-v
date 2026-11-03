module hammer_v5_fetch_path (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_addr,
    input wire [1:0] req_cmd,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error, rsp_page_fault,
    output wire [31:0] rsp_insn_raw,
    output wire [2:0] rsp_insn_bytes,
    output wire rsp_illegal,
    output wire [63:0] rsp_tval,
    output wire tr_valid,
    input wire tr_ready,
    output wire [63:0] tr_va,
    input wire tr_rsp_valid,
    output wire tr_rsp_ready,
    input wire [55:0] tr_pa,
    input wire tr_page_fault, tr_access_fault,
    output wire cache_valid,
    input wire cache_ready,
    output wire [63:0] cache_addr,
    output wire [1:0] cache_cmd,
    input wire cache_rsp_valid,
    output wire cache_rsp_ready,
    input wire [63:0] cache_rdata,
    input wire cache_error
);
    localparam [2:0] IDLE=0, TRANSLATE=1, TWAIT=2,
        ISSUE=3, CWAIT=4, RESPONSE=5;
    reg [2:0] state;
    reg [63:0] pc_q, va_q, physical_q, tval_q;
    reg [31:0] raw_q, expanded_q;
    reg [15:0] first_half_q;
    reg [2:0] bytes_q;
    reg [1:0] cmd_q;
    reg second_q, error_q, page_q, illegal_q;
    wire [15:0] first_half = pc_q[1] ? cache_rdata[31:16] : cache_rdata[15:0];
    wire [31:0] decompressed;
    wire compressed_illegal;

    hammer_v5_decompress u_decompress (
        .insn16(first_half), .insn32(decompressed), .illegal(compressed_illegal)
    );
    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_rdata = rsp_valid && !error_q && !page_q ?
        {32'b0,expanded_q} : 64'b0;
    assign rsp_insn_raw = rsp_valid && !error_q && !page_q ? raw_q : 32'b0;
    assign rsp_insn_bytes = rsp_valid && !cmd_q[1] ? bytes_q : 3'b0;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_page_fault = rsp_valid && page_q;
    assign rsp_illegal = rsp_valid && illegal_q;
    assign rsp_tval = rsp_valid && (error_q || page_q || illegal_q) ? tval_q : 64'b0;
    assign tr_valid = rst_n && state == TRANSLATE;
    assign tr_va = tr_valid ? va_q : 64'b0;
    assign tr_rsp_ready = rst_n && state == TWAIT;
    assign cache_valid = rst_n && state == ISSUE;
    assign cache_addr = cache_valid ? physical_q : 64'b0;
    assign cache_cmd = cache_valid ? cmd_q : 2'b0;
    assign cache_rsp_ready = rst_n && state == CWAIT;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            pc_q <= 0;
            va_q <= 0;
            physical_q <= 0;
            tval_q <= 0;
            raw_q <= 0;
            expanded_q <= 0;
            first_half_q <= 0;
            bytes_q <= 0;
            cmd_q <= 0;
            second_q <= 0;
            error_q <= 0;
            page_q <= 0;
            illegal_q <= 0;
        end else begin
            case (state)
                IDLE: if (req_valid) begin
                    pc_q <= req_addr;
                    va_q <= req_addr;
                    physical_q <= req_addr;
                    tval_q <= 0;
                    raw_q <= 0;
                    expanded_q <= 0;
                    first_half_q <= 0;
                    bytes_q <= 0;
                    cmd_q <= req_cmd;
                    second_q <= 0;
                    error_q <= 0;
                    page_q <= 0;
                    illegal_q <= 0;
                    if (req_cmd[1]) state <= ISSUE;
                    else if (req_addr[0]) begin
                        error_q <= 1;
                        tval_q <= req_addr;
                        state <= RESPONSE;
                    end else state <= TRANSLATE;
                end
                TRANSLATE: if (tr_ready) state <= TWAIT;
                TWAIT: if (tr_rsp_valid) begin
                    physical_q <= {8'b0,tr_pa[55:2],2'b0};
                    error_q <= tr_access_fault;
                    page_q <= tr_page_fault;
                    if (tr_access_fault || tr_page_fault) begin
                        tval_q <= va_q;
                        state <= RESPONSE;
                    end else state <= ISSUE;
                end
                ISSUE: if (cache_ready) state <= CWAIT;
                CWAIT: if (cache_rsp_valid) begin
                    if (cache_error) begin
                        error_q <= 1;
                        tval_q <= va_q;
                        state <= RESPONSE;
                    end else if (cmd_q[1]) state <= RESPONSE;
                    else if (second_q) begin
                        raw_q <= {cache_rdata[15:0],first_half_q};
                        expanded_q <= {cache_rdata[15:0],first_half_q};
                        bytes_q <= 4;
                        state <= RESPONSE;
                    end else if (first_half[1:0] != 2'b11) begin
                        raw_q <= {16'b0,first_half};
                        expanded_q <= decompressed;
                        bytes_q <= 2;
                        illegal_q <= compressed_illegal;
                        if (compressed_illegal) tval_q <= {48'b0,first_half};
                        state <= RESPONSE;
                    end else if (pc_q[1]) begin
                        first_half_q <= first_half;
                        va_q <= pc_q + 64'd2;
                        second_q <= 1;
                        state <= TRANSLATE;
                    end else begin
                        raw_q <= cache_rdata[31:0];
                        expanded_q <= cache_rdata[31:0];
                        bytes_q <= 4;
                        state <= RESPONSE;
                    end
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
