module hammer_v5_vector (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [31:0] req_insn,
    input wire [63:0] req_rs1_data, req_rs2_data,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_data,
    output wire rsp_illegal, rsp_mem_error, rsp_page_fault,
    output wire [63:0] rsp_tval,
    input wire commit_valid, abort_valid,
    output wire [3:0] event_macs,
    output wire mem_req_valid, mem_req_write,
    input wire mem_req_ready,
    output wire [63:0] mem_req_addr, mem_req_wdata,
    output wire [7:0] mem_req_wstrb,
    input wire mem_rsp_valid, mem_rsp_error, mem_rsp_page_fault,
    input wire [63:0] mem_rsp_rdata,
    output wire mem_rsp_ready
);
    localparam [2:0] IDLE=0, INT8_WAIT=1, BF16_WAIT=2,
        MEM_REQUEST=3, MEM_WAIT=4, RESPONSE=5, DISPOSITION=6;
    reg [2:0] state, op_q;
    reg [2:0] dest_q;
    reg [63:0] addr_q, write_q, data_q;
    reg illegal_q, error_q, page_q;
    reg [63:0] vr [0:7];
    wire [2:0] operation = req_insn[14:12];
    reg legal;
    wire i8_ready, i8_valid, bf_ready, bf_valid;
    wire [63:0] i8_data, bf_data;
    wire accept = req_valid && req_ready;
    wire response_transfer = rsp_valid && rsp_ready;
    wire can_dispose = state == DISPOSITION || response_transfer;
    wire success = !illegal_q && !error_q && !page_q;
    wire commit = rst_n && commit_valid && !abort_valid && can_dispose && success;
    integer n;

    always @* begin
        legal = req_insn[6:0] == 7'h0b && req_insn[31:25] == 0;
        case (operation)
            3'b000: legal = legal && req_insn[24:20] == 0 &&
                req_insn[11:10] == 0;
            3'b001,3'b010: legal = legal && req_insn[19:18] == 0 &&
                req_insn[24:23] == 0;
            3'b011: legal = legal && req_insn[19:18] == 0;
            3'b100: legal = legal && req_insn[24:23] == 0 &&
                req_insn[11:7] == 0;
            default: legal = 1'b0;
        endcase
    end
    assign req_ready = rst_n && state == IDLE && i8_ready && bf_ready;
    assign rsp_valid = rst_n && ((state == INT8_WAIT && i8_valid) ||
        (state == BF16_WAIT && bf_valid) || state == RESPONSE);
    assign rsp_data = !rsp_valid || !success ? 64'b0 :
        state == INT8_WAIT ? i8_data :
        state == BF16_WAIT ? bf_data : data_q;
    assign rsp_illegal = rsp_valid && illegal_q;
    assign rsp_mem_error = rsp_valid && error_q;
    assign rsp_page_fault = rsp_valid && page_q;
    assign rsp_tval = rsp_valid && (error_q || page_q) ? addr_q : 64'b0;
    assign event_macs = !commit ? 4'd0 : op_q == 2 ? 4'd4 :
        (op_q == 1 || op_q == 3) ? 4'd8 : 4'd0;
    assign mem_req_valid = rst_n && state == MEM_REQUEST;
    assign mem_req_write = mem_req_valid && op_q == 4;
    assign mem_req_addr = mem_req_valid ? addr_q : 64'b0;
    assign mem_req_wdata = mem_req_write ? write_q : 64'b0;
    assign mem_req_wstrb = mem_req_write ? 8'hff : 8'b0;
    assign mem_rsp_ready = rst_n && state == MEM_WAIT;

    hammer_v5_int8 u_int8 (
        .clk(clk), .rst_n(rst_n),
        .req_valid(accept && legal && (operation == 1 || operation == 3)),
        .req_ready(i8_ready), .req_a(vr[req_insn[17:15]]),
        .req_b(vr[req_insn[22:20]]), .req_seed(req_rs2_data),
        .req_square(operation == 3), .rsp_valid(i8_valid),
        .rsp_ready(state == INT8_WAIT && rsp_ready), .rsp_data(i8_data)
    );
    hammer_v5_bf16 u_bf16 (
        .clk(clk), .rst_n(rst_n),
        .req_valid(accept && legal && operation == 2), .req_ready(bf_ready),
        .req_a(vr[req_insn[17:15]]), .req_b(vr[req_insn[22:20]]),
        .rsp_valid(bf_valid), .rsp_ready(state == BF16_WAIT && rsp_ready),
        .rsp_data(bf_data)
    );
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            op_q <= 0;
            dest_q <= 0;
            addr_q <= 0;
            write_q <= 0;
            data_q <= 0;
            illegal_q <= 0;
            error_q <= 0;
            page_q <= 0;
            for (n = 0; n < 8; n = n + 1) vr[n] <= 0;
        end else begin
            case (state)
                IDLE: if (accept) begin
                    op_q <= operation;
                    dest_q <= req_insn[9:7];
                    addr_q <= req_rs1_data;
                    write_q <= vr[req_insn[22:20]];
                    data_q <= 0;
                    illegal_q <= !legal;
                    error_q <= 0;
                    page_q <= 0;
                    if (!legal) state <= RESPONSE;
                    else case (operation)
                        3'b001,3'b011: state <= INT8_WAIT;
                        3'b010: state <= BF16_WAIT;
                        default: begin
                            if (|req_rs1_data[2:0]) begin
                                error_q <= 1;
                                state <= RESPONSE;
                            end else state <= MEM_REQUEST;
                        end
                    endcase
                end
                MEM_REQUEST: if (mem_req_ready) state <= MEM_WAIT;
                MEM_WAIT: if (mem_rsp_valid) begin
                    data_q <= op_q == 0 && !mem_rsp_error && !mem_rsp_page_fault ?
                        mem_rsp_rdata : 64'b0;
                    error_q <= mem_rsp_error;
                    page_q <= mem_rsp_page_fault;
                    state <= RESPONSE;
                end
                INT8_WAIT,BF16_WAIT,RESPONSE: if (response_transfer) begin
                    if (commit_valid || abort_valid) state <= IDLE;
                    else state <= DISPOSITION;
                end
                DISPOSITION: if (commit_valid || abort_valid) state <= IDLE;
                default: state <= IDLE;
            endcase
            if (commit && op_q == 0) vr[dest_q] <= data_q;
        end
    end
endmodule
