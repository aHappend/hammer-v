module hammer_v3_fetch_path (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [63:0] req_addr,
    input wire [1:0] req_cmd,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error, rsp_page_fault,
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
    localparam [2:0] IDLE=0, TRANSLATE=1, TWAIT=2, ISSUE=3, CWAIT=4, RESPONSE=5;
    reg [2:0] state;
    reg [63:0] addr_q, read_q;
    reg [1:0] cmd_q;
    reg error_q, page_q;
    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_rdata = rsp_valid && !error_q && !page_q ? read_q : 64'b0;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_page_fault = rsp_valid && page_q;
    assign tr_valid = rst_n && state == TRANSLATE;
    assign tr_va = tr_valid ? addr_q : 64'b0;
    assign tr_rsp_ready = rst_n && state == TWAIT;
    assign cache_valid = rst_n && state == ISSUE;
    assign cache_addr = cache_valid ? addr_q : 64'b0;
    assign cache_cmd = cache_valid ? cmd_q : 2'b0;
    assign cache_rsp_ready = rst_n && state == CWAIT;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            addr_q <= 0;
            read_q <= 0;
            cmd_q <= 0;
            error_q <= 0;
            page_q <= 0;
        end else begin
            case (state)
                IDLE: if (req_valid) begin
                    addr_q <= req_addr;
                    cmd_q <= req_cmd;
                    read_q <= 0;
                    error_q <= 0;
                    page_q <= 0;
                    if (req_cmd[1]) state <= ISSUE;
                    else if (|req_addr[1:0]) begin
                        error_q <= 1;
                        state <= RESPONSE;
                    end else state <= TRANSLATE;
                end
                TRANSLATE: if (tr_ready) state <= TWAIT;
                TWAIT: if (tr_rsp_valid) begin
                    addr_q <= {8'b0,tr_pa};
                    error_q <= tr_access_fault;
                    page_q <= tr_page_fault;
                    if (tr_access_fault || tr_page_fault) state <= RESPONSE;
                    else state <= ISSUE;
                end
                ISSUE: if (cache_ready) state <= CWAIT;
                CWAIT: if (cache_rsp_valid) begin
                    read_q <= cache_rdata;
                    error_q <= cache_error;
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
