module hammer_v3_data_path #(
    parameter integer DMEM_WORDS = 8192
) (
    input wire clk, rst_n,
    input wire req_valid, req_physical,
    output wire req_ready,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    input wire [1:0] req_cmd, req_size, req_access,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error, rsp_page_fault,
    input wire at_req_valid,
    output wire at_req_ready,
    input wire [63:0] at_req_va,
    input wire [1:0] at_req_access,
    output wire at_rsp_valid,
    input wire at_rsp_ready,
    output wire [55:0] at_rsp_pa,
    output wire at_rsp_error, at_rsp_page_fault,
    output wire tr_valid,
    input wire tr_ready,
    output wire [63:0] tr_va,
    output wire [1:0] tr_access,
    input wire tr_rsp_valid,
    output wire tr_rsp_ready,
    input wire [55:0] tr_pa,
    input wire tr_page_fault, tr_access_fault,
    output wire out_valid,
    input wire out_ready,
    output wire [63:0] out_addr, out_wdata,
    output wire [7:0] out_wstrb,
    output wire [1:0] out_cmd, out_size,
    input wire out_rsp_valid,
    output wire out_rsp_ready,
    input wire [63:0] out_rdata,
    input wire out_error
);
    localparam [2:0] IDLE=0, TRANSLATE=1, TWAIT=2, ISSUE=3, DWAIT=4, RESPONSE=5;
    localparam [63:0] LIMIT = 64'h10000000 + DMEM_WORDS*64'd8;
    reg [2:0] state;
    reg atomic_q, error_q, page_q;
    reg [63:0] addr_q, write_q, read_q;
    reg [7:0] mask_q;
    reg [1:0] cmd_q, size_q, access_q;
    wire atomic_target = (tr_pa >= 56'h10000000 && tr_pa < LIMIT) ||
        (tr_pa >= 56'h80000000 && tr_pa < 56'h100000000);
    assign req_ready = rst_n && state == IDLE && !at_req_valid;
    assign at_req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE && !atomic_q;
    assign at_rsp_valid = rst_n && state == RESPONSE && atomic_q;
    assign rsp_rdata = rsp_valid && !error_q && !page_q ? read_q : 64'b0;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_page_fault = rsp_valid && page_q;
    assign at_rsp_pa = at_rsp_valid && !error_q && !page_q ? addr_q[55:0] : 56'b0;
    assign at_rsp_error = at_rsp_valid && error_q;
    assign at_rsp_page_fault = at_rsp_valid && page_q;
    assign tr_valid = rst_n && state == TRANSLATE;
    assign tr_va = tr_valid ? addr_q : 64'b0;
    assign tr_access = tr_valid ? access_q : 2'b0;
    assign tr_rsp_ready = rst_n && state == TWAIT;
    assign out_valid = rst_n && state == ISSUE;
    assign out_addr = out_valid ? addr_q : 64'b0;
    assign out_wdata = out_valid ? write_q : 64'b0;
    assign out_wstrb = out_valid ? mask_q : 8'b0;
    assign out_cmd = out_valid ? cmd_q : 2'b0;
    assign out_size = out_valid ? size_q : 2'b0;
    assign out_rsp_ready = rst_n && state == DWAIT;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            atomic_q <= 0;
            error_q <= 0;
            page_q <= 0;
            addr_q <= 0;
            write_q <= 0;
            read_q <= 0;
            mask_q <= 0;
            cmd_q <= 0;
            size_q <= 0;
            access_q <= 0;
        end else begin
            case (state)
                IDLE: if (at_req_valid || req_valid) begin
                    atomic_q <= at_req_valid;
                    addr_q <= at_req_valid ? at_req_va : req_addr;
                    access_q <= at_req_valid ? at_req_access : req_access;
                    cmd_q <= at_req_valid ? 2'b0 : req_cmd;
                    size_q <= at_req_valid ? 2'b0 : req_size;
                    write_q <= at_req_valid ? 64'b0 : req_wdata;
                    mask_q <= at_req_valid ? 8'b0 : req_wstrb;
                    read_q <= 0;
                    error_q <= 0;
                    page_q <= 0;
                    if (!at_req_valid && (req_cmd[1] || req_physical))
                        state <= ISSUE;
                    else state <= TRANSLATE;
                end
                TRANSLATE: if (tr_ready) state <= TWAIT;
                TWAIT: if (tr_rsp_valid) begin
                    addr_q <= {8'b0,tr_pa};
                    page_q <= tr_page_fault;
                    error_q <= tr_access_fault ||
                        (atomic_q && !tr_page_fault && !atomic_target);
                    if (atomic_q || tr_page_fault || tr_access_fault)
                        state <= RESPONSE;
                    else state <= ISSUE;
                end
                ISSUE: if (out_ready) state <= DWAIT;
                DWAIT: if (out_rsp_valid) begin
                    read_q <= out_rdata;
                    error_q <= out_error;
                    state <= RESPONSE;
                end
                RESPONSE: if (atomic_q ? at_rsp_ready : rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
