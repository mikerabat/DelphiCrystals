program kyber_test;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  StrUtils,
  kyber in '..\src\kyber.pas',
  fips202 in '..\src\fips202.pas',
  cryptRnd in '..\src\cryptRnd.pas',
  kybertests in 'kybertests.pas';

const nTests = 1000;

var x1 : UInt16;
    u1 : UInt16;
    i : integer;
    b11, b12, b13 : boolean;
    b21, b22, b23 : boolean;
    b31, b32, b33 : boolean;
begin
     try

        // test if sign extension works in delphi to simulate arithmetic shifts
        x1 := UInt16(-3);

        u1 := UInt16( Integer( Int16(x1) ) shr 15 );

        Writeln('Sign of x1: ', u1);

        // ###########################################
        // #### Test keyber
        b11 := True;
        b12 := True;
        b13 := True;

        for i := 0 to nTests - 1 do
        begin
             b11 := TestKeys512 and b11;
             b12 := test_invalid_sk_512 and b12;
             b13 := test_Invalid_ciphertext_512 and b13;
        end;

        b21 := True;
        b22 := True;
        b23 := True;

        for i := 0 to nTests - 1 do
        begin
             b21 := TestKeys768 and b21;
             b22 := test_invalid_sk_768 and b22;
             b23 := test_Invalid_ciphertext_768 and b23;
        end;

        b31 := True;
        b32 := True;
        b33 := True;
        for i := 0 to nTests - 1 do
        begin
             b31 := TestKeys1024 and b31;
             b32 := test_invalid_sk_1024 and b32;
             b33 := test_Invalid_ciphertext_1024 and b33;
        end;

        Writeln;

        Writeln('Kyber 512');
        Writeln('Overall test keys result: ' + Ifthen( b11, 'SUCCESS', 'FAILED'));
        Writeln('Overall test sk change result: ' + Ifthen( b12, 'SUCCESS', 'FAILED'));
        Writeln('Overall test ciphertext change result: ' + Ifthen( b13, 'SUCCESS', 'FAILED'));

        Writeln;
        Writeln('Kyber 768');
        Writeln('Overall test keys result: ' + Ifthen( b21, 'SUCCESS', 'FAILED'));
        Writeln('Overall test sk change result: ' + Ifthen( b22, 'SUCCESS', 'FAILED'));
        Writeln('Overall test ciphertext change result: ' + Ifthen( b23, 'SUCCESS', 'FAILED'));

        Writeln;
        Writeln('Kyber 1024');
        Writeln('Overall test keys result: ' + Ifthen( b31, 'SUCCESS', 'FAILED'));
        Writeln('Overall test sk change result: ' + Ifthen( b32, 'SUCCESS', 'FAILED'));
        Writeln('Overall test ciphertext change result: ' + Ifthen( b33, 'SUCCESS', 'FAILED'));

        Writeln('Hit enter to continue...');
        readln;
     except
           on E: Exception do
              Writeln(E.ClassName, ': ', E.Message);
     end;
end.
