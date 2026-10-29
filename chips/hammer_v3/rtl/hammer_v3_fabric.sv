module hammer_v3_fabric #(
    parameter integer IMEM_WORDS = 16384,
    parameter integer DMEM_WORDS = 8192
) (
    input wire clk, rst_n,
    input wire [2:0] req_valid, req_write,
    output wire [2:0] req_ready,
    input wire [191:0] req_addr, req_wdata,
    input wire [23:0] req_wstrb,
    input wire [8:0] req_prot,
    output wire [2:0] rsp_valid, rsp_error, rsp_decerr,
    input wire [2:0] rsp_ready,
    output wire [191:0] rsp_rdata,
    input wire h_imem, h_dmem, h_write,
    input wire [31:0] h_addr,
    input wire [63:0] h_wdata,
    input wire [7:0] h_wstrb,
    output wire [63:0] h_imem_data, h_dmem_data,
    output wire mem_valid, mem_write,
    input wire mem_ready,
    output wire [63:0] mem_addr, mem_wdata,
    output wire [7:0] mem_wstrb,
    output wire [2:0] mem_prot,
    input wire mem_rsp_valid, mem_error, mem_decerr,
    output wire mem_rsp_ready,
    input wire [63:0] mem_rdata
);
    localparam [1:0] IDLE=0, ISSUE=1, WAITING=2, RESPONSE=3;
    localparam [63:0] ILIMIT = IMEM_WORDS*64'd4;
    localparam [63:0] DLIMIT = 64'h10000000 + DMEM_WORDS*64'd8;
    reg [1:0] state, owner, next_owner, target;
    reg [63:0] addr_q, write_q, read_q;
    reg [7:0] mask_q;
    reg [2:0] prot_q;
    reg write_enable, error_q, decerr_q;
    reg [1:0] select;
    wire [63:0] selected_addr = req_addr[select*64 +: 64];
    wire selected_write = req_write[select];
    wire selected_instruction = select == 0;
    wire region_i = selected_addr < ILIMIT && selected_instruction && !selected_write;
    wire region_d = selected_addr >= 64'h10000000 && selected_addr < DLIMIT &&
        !selected_instruction;
    wire region_ext = selected_addr >= 64'h80000000 &&
        selected_addr < 64'h100000000 && (!selected_instruction || !selected_write);
    wire bad = |selected_addr[2:0] || !(region_i || region_d || region_ext);
    wire i_ready, i_valid, i_error, d_ready, d_valid, d_error;
    wire [63:0] i_data, d_data;
    wire i_request = rst_n && state == ISSUE && target == 0;
    wire d_request = rst_n && state == ISSUE && target == 1;
    wire target_ready = target == 0 ? i_ready : target == 1 ? d_ready : mem_ready;
    wire target_valid = target == 0 ? i_valid : target == 1 ? d_valid : mem_rsp_valid;
    wire target_error = target == 0 ? i_error : target == 1 ? d_error : mem_error;
    wire [63:0] target_data = target == 0 ? i_data : target == 1 ? d_data : mem_rdata;
    wire consume = rst_n && state == WAITING;
    always @* begin
        select = next_owner;
        case (next_owner)
            0: if (req_valid[0]) select = 0;
               else if (req_valid[1]) select = 1;
               else select = 2;
            1: if (req_valid[1]) select = 1;
               else if (req_valid[2]) select = 2;
               else select = 0;
            default: if (req_valid[2]) select = 2;
                     else if (req_valid[0]) select = 0;
                     else select = 1;
        endcase
    end
    assign req_ready = rst_n && state == IDLE && |req_valid ?
        3'b001 << select : 3'b0;
    assign rsp_valid = rst_n && state == RESPONSE ? 3'b001 << owner : 3'b0;
    assign rsp_error = rsp_valid & {3{error_q}};
    assign rsp_decerr = rsp_valid & {3{decerr_q}};
    for (genvar n = 0; n < 3; n = n + 1) begin : g_response
        assign rsp_rdata[n*64 +: 64] = rsp_valid[n] && !error_q ? read_q : 64'b0;
    end
    assign mem_valid = rst_n && state == ISSUE && target == 2;
    assign mem_write = mem_valid && write_enable;
    assign mem_addr = mem_valid ? addr_q : 64'b0;
    assign mem_wdata = mem_valid ? write_q : 64'b0;
    assign mem_wstrb = mem_valid ? mask_q : 8'b0;
    assign mem_prot = mem_valid ? prot_q : 3'b0;
    assign mem_rsp_ready = consume && target == 2;
    hammer_v2_imem #(.WORDS(IMEM_WORDS)) u_imem (
        .clk(clk), .rst_n(rst_n), .req_valid(i_request), .req_ready(i_ready),
        .req_write(write_enable), .req_addr(addr_q), .req_wdata(write_q),
        .req_wstrb(mask_q), .rsp_valid(i_valid), .rsp_ready(consume && target == 0),
        .rsp_rdata(i_data), .rsp_error(i_error),
        .h_req(h_imem), .h_write(h_write), .h_addr(h_addr),
        .h_wdata(h_wdata), .h_wstrb(h_wstrb), .h_rdata(h_imem_data)
    );
    hammer_v2_dmem #(.WORDS(DMEM_WORDS)) u_dmem (
        .clk(clk), .rst_n(rst_n), .req_valid(d_request), .req_ready(d_ready),
        .req_write(write_enable), .req_addr(addr_q), .req_wdata(write_q),
        .req_wstrb(mask_q), .rsp_valid(d_valid), .rsp_ready(consume && target == 1),
        .rsp_rdata(d_data), .rsp_error(d_error),
        .h_req(h_dmem), .h_write(h_write), .h_addr(h_addr),
        .h_wdata(h_wdata), .h_wstrb(h_wstrb), .h_rdata(h_dmem_data)
    );
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            owner <= 0;
            next_owner <= 0;
            target <= 0;
            addr_q <= 0;
            write_q <= 0;
            read_q <= 0;
            mask_q <= 0;
            prot_q <= 0;
            write_enable <= 0;
            error_q <= 0;
            decerr_q <= 0;
        end else begin
            case (state)
                IDLE: if (|req_valid) begin
                    owner <= select;
                    next_owner <= select == 2 ? 2'd0 : select + 2'd1;
                    addr_q <= selected_addr;
                    write_q <= req_wdata[select*64 +: 64];
                    mask_q <= req_wstrb[select*8 +: 8];
                    prot_q <= req_prot[select*3 +: 3];
                    write_enable <= selected_write;
                    read_q <= 0;
                    error_q <= bad;
                    decerr_q <= bad;
                    if (region_i) target <= 0;
                    else if (region_d) target <= 1;
                    else target <= 2;
                    if (bad) state <= RESPONSE;
                    else state <= ISSUE;
                end
                ISSUE: if (target_ready) state <= WAITING;
                WAITING: if (target_valid) begin
                    read_q <= target_data;
                    error_q <= target_error;
                    decerr_q <= target == 2 && mem_decerr;
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready[owner]) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
