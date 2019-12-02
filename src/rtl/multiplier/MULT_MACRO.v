// A very basic and non-optimized replacement for MULT
// This was intended to be inside a DSP module in the Xilinx FPGAs

module MULT #(
      parameter DEVICE = "7SERIES",
      parameter LATENCY = 3,
      parameter WIDTH_A = 25,
      parameter WIDTH_B = 18
  )
  (
    input wire CLK,
    input wire RST,
    input wire CE,

    input wire [WIDTH_A-1 : 0] A,
    input wire [WIDTH_B-1 : 0] B,

    output wire [WIDTH_A+WIDTH_B-1 : 0] P
  );

  reg [WIDTH_A+WIDTH_B-1 : 0] P_A [0:LATENCY];
  always @* P_A[0] = A*B; // Highly inneficient, I know
  
  genvar i;
  generate
    for(i = 0; i < LATENCY; i=i+1) begin: LATENCY_REG
      always @(posedge CLK) 
        if(RST)
          P_A[i+1] <= 0;
        else
          P_A[i+1] <= P_A[i];
    end
  endgenerate
  
  assign P = P_A[LATENCY];
endmodule
