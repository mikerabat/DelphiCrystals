// ###################################################################
// #### This file is part of the Crystals cryptographic algorithm library.
// #### A direct port of the reference C implementation.
// ####
// #### Copyright:(c) 2026, Michael R. . All rights reserved.
// ####
// #### Unless required by applicable law or agreed to in writing, software
// #### distributed under the License is distributed on an "AS IS" BASIS,
// #### WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// #### See the License for the specific language governing permissions and
// #### limitations under the License.
// ###################################################################

unit kyberTests;

// a shared testing unit for the kyber routines - can be used in FPC and Delphi

{$IFDEF FPC}
{$mode Delphi}
{$ENDIF}

interface

uses
  Classes, SysUtils, kyber;


function TestKeys768 : boolean;
function test_invalid_sk_768 : boolean;
function test_Invalid_ciphertext_768 : boolean;


function TestKeys512 : boolean;
function test_invalid_sk_512 : boolean;
function test_Invalid_ciphertext_512 : boolean;


function TestKeys1024 : boolean;
function test_invalid_sk_1024 : boolean;
function test_Invalid_ciphertext_1024 : boolean;


implementation

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

function test_invalid_sk_768 : boolean;
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

function test_Invalid_ciphertext_768 : boolean;
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

function test_invalid_sk_512 : boolean;
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

function test_Invalid_ciphertext_512 : boolean;
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

function test_invalid_sk_1024 : boolean;
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

function test_Invalid_ciphertext_1024 : boolean;
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

end.

