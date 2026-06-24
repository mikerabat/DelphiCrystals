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
program dilithium_test;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  StrUtils,
  fips202 in '..\src\fips202.pas',
  dilithium in '..\src\dilithium.pas',
  cryptRnd in '..\src\cryptRnd.pas',
  dilithiumtests in 'dilithiumtests.pas';

var res2, res3, res5: boolean;
begin
  try
    Writeln('Simple "shake256" test');
    TestShake;

    Writeln('Test Dilithium 5');
    res5 := TestSign_Dilithium_5;
    Writeln('Test Dilithium 3');
    res3 := TestSign_Dilithium_3;
    Writeln('Test Dilithium 2');
    res2 := TestSign_Dilithium_2;

    Writeln;
    Writeln('Overall Result:');
    Writeln('Dilithium 5: ', Ifthen( res5, 'SUCCESS', 'FAILED'));
    Writeln('Dilithium 3: ', Ifthen( res3, 'SUCCESS', 'FAILED'));
    Writeln('Dilithium 2: ', Ifthen( res2, 'SUCCESS', 'FAILED'));


    Writeln('Hit enter to end...');
    readln
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
