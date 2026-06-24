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

unit cryptRnd;

interface

procedure CryptRandom( var buf; len : integer );

implementation

{$IFDEF MSWINDOWS}

// ###########################################
// #### Random - use windows internal bcrypt library
// ###########################################
type
  ULONG = Cardinal; // from windows.pas
  BCrypt_ALG_HANDLE = Pointer;

const BCRYPT_USE_SYSTEM_PREFERRED_RNG = $00000002;   // hAlgorithm needs to be null then

function BCryptGenRandom(hAlgorith : BCRYPT_ALG_HANDLE; pbBuffer : PByte;
                               cbBuffer : ULong; dwFlags : ULong ) : Longint; stdcall; external 'BCrypt.dll';

procedure CryptRandom( var buf; len : integer );
begin
     BCryptGenRandom(nil, @buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
end;

{$ENDIF}

// ###########################################
// #### Linux random
// ###########################################

{$IFDEF LINUX}

uses ctypes;

// this is not defined in BaseUnix -> define the syscall!
function fpgetrandom(var buf; buflen : csize_t; flags : cuint) : csize_t; cdecl; external 'c' name 'getrandom';

procedure CryptRandom( var buf; len : integer );
begin
     if len <= 0 then
        exit;

     fpgetrandom(buf, len, 0);
end;
{$ENDIF}

end.
