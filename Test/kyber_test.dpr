program kyber_test;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  StrUtils,
  kyber in '..\src\kyber.pas',
  fips202 in '..\src\fips202.pas',
  cryptRnd in '..\src\cryptRnd.pas';

function TestKeys768 : boolean;
var pk : TKyber768PublicKeyBytes;
    sk : TKyber768SecretKeyBytes;
    ct : TKyber768CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
begin
     // alice generates a key
     kyber768_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber768_kem_enc(ct, key_b, pk);

     // alice uses bobs response to get her shared key
     kyber768_kem_dec( key_a, ct, sk );

     Result := CompareMem( @key_a[0], @key_b[0], sizeof(key_a));

     if Result
     then
         Writeln( 'SUCCESS - Key derrive')
     else
         Writeln( 'FAILED - Key derrive');
end;

function test_invalid_sk_a768 : boolean;
var pk : TKyber768PublicKeyBytes;
    sk : TKyber768SecretKeyBytes;
    ct : TKyber768CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    i : integer;
begin
     // alice generates a key
     kyber768_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber768_kem_enc(ct, key_b, pk);

     // Replace secret key with random values
     for i := 0 to Length(sk) - 1 do
         sk[i] := Byte( Random($FF));

     // alice uses bobs response to get her shared key
     kyber768_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS: keys do not match as expected')
     else
         Writeln( 'FAILED - Error invalid sk');
end;

function test_Invalid_ciphertexst768 : boolean;
var pk : TKyber768PublicKeyBytes;
    sk : TKyber768SecretKeyBytes;
    ct : TKyber768CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    b : byte;
    pos : integer;
begin
     b := random(254) + 1;
     pos := random( 768 );  // min of all implementations

     // alice generates a key
     kyber768_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber768_kem_enc(ct, key_b, pk);


     // change some byte in the ciphertext (i.e., encapsulated key)
     ct[pos] := ct[pos] xor b;


     // alice uses bobs response to get her shared key
     kyber768_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS - Key change detected')
     else
         Writeln( 'FAILED - invalid ciphertext');
end;

function TestKeys512 : boolean;
var pk : TKyber512PublicKeyBytes;
    sk : TKyber512SecretKeyBytes;
    ct : TKyber512CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
begin
     // alice generates a key
     kyber512_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber512_kem_enc(ct, key_b, pk);

     // alice uses bobs response to get her shared key
     kyber512_kem_dec( key_a, ct, sk );

     Result := CompareMem( @key_a[0], @key_b[0], sizeof(key_a));

     if Result
     then
         Writeln( 'SUCCESS - Key derrive')
     else
         Writeln( 'FAILED - Key derrive');
end;

function test_invalid_sk_a512 : boolean;
var pk : TKyber512PublicKeyBytes;
    sk : TKyber512SecretKeyBytes;
    ct : TKyber512CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    i : integer;
begin
     // alice generates a key
     kyber512_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber512_kem_enc(ct, key_b, pk);

     // Replace secret key with random values
     for i := 0 to Length(sk) - 1 do
         sk[i] := Byte( Random($FF));

     // alice uses bobs response to get her shared key
     kyber512_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS: keys do not match as expected')
     else
         Writeln( 'FAILED - Error invalid sk');
end;

function test_Invalid_ciphertexst512 : boolean;
var pk : TKyber512PublicKeyBytes;
    sk : TKyber512SecretKeyBytes;
    ct : TKyber512CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    b : byte;
    pos : integer;
begin
     b := random(254) + 1;
     pos := random( 512 );  // min of all implementations

     // alice generates a key
     kyber512_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber512_kem_enc(ct, key_b, pk);


     // change some byte in the ciphertext (i.e., encapsulated key)
     ct[pos] := ct[pos] xor b;


     // alice uses bobs response to get her shared key
     kyber512_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS - Key change detected')
     else
         Writeln( 'FAILED - invalid ciphertext');
end;


function TestKeys1024 : boolean;
var pk : TKyber1024PublicKeyBytes;
    sk : TKyber1024SecretKeyBytes;
    ct : TKyber1024CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
begin
     // alice generates a key
     kyber1024_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber1024_kem_enc(ct, key_b, pk);

     // alice uses bobs response to get her shared key
     kyber1024_kem_dec( key_a, ct, sk );

     Result := CompareMem( @key_a[0], @key_b[0], sizeof(key_a));

     if Result
     then
         Writeln( 'SUCCESS - Key derrive')
     else
         Writeln( 'FAILED - Key derrive');
end;

function test_invalid_sk_a1024 : boolean;
var pk : TKyber1024PublicKeyBytes;
    sk : TKyber1024SecretKeyBytes;
    ct : TKyber1024CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    i : integer;
begin
     // alice generates a key
     kyber1024_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber1024_kem_enc(ct, key_b, pk);

     // Replace secret key with random values
     for i := 0 to Length(sk) - 1 do
         sk[i] := Byte( Random($FF));

     // alice uses bobs response to get her shared key
     kyber1024_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS: keys do not match as expected')
     else
         Writeln( 'FAILED - Error invalid sk');
end;

function test_Invalid_ciphertexst1024 : boolean;
var pk : TKyber1024PublicKeyBytes;
    sk : TKyber1024SecretKeyBytes;
    ct : TKyber1024CipherTextBytes;
    key_b : TKyberSharedSecretBytes;
    key_a : TKyberSharedSecretBytes;
    b : byte;
    pos : integer;
begin
     b := random(254) + 1;
     pos := random( 1024 );  // min of all implementations

     // alice generates a key
     kyber1024_kem_keypair( pk, sk );

     // bob derives a secret key and creates a response
     kyber1024_kem_enc(ct, key_b, pk);


     // change some byte in the ciphertext (i.e., encapsulated key)
     ct[pos] := ct[pos] xor b;


     // alice uses bobs response to get her shared key
     kyber1024_kem_dec( key_a, ct, sk );

     Result := not CompareMem( @key_a[0], @key_b[0], sizeof(key_a));
     if Result
     then
         Writeln( 'SUCCESS - Key change detected')
     else
         Writeln( 'FAILED - invalid ciphertext');
end;



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
          b12 := test_invalid_sk_a512 and b12;
          b13 := test_Invalid_ciphertexst512 and b13;
     end;

     b21 := True;
     b22 := True;
     b23 := True;

     for i := 0 to nTests - 1 do
     begin
          b21 := TestKeys768 and b21;
          b22 := test_invalid_sk_a768 and b22;
          b23 := test_Invalid_ciphertexst768 and b23;
     end;

     b31 := True;
     b32 := True;
     b33 := True;
     for i := 0 to nTests - 1 do
     begin
          b31 := TestKeys1024 and b31;
          b32 := test_invalid_sk_a1024 and b32;
          b33 := test_Invalid_ciphertexst1024 and b33;
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
