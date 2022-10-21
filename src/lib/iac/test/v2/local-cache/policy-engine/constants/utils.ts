import * as os from 'os';

const policyEngineChecksums = `
101c5a91ef7bc8918592e4536d5439d03f8a7586b278f058feb33240b361519e  snyk-iac-test_0.35.2_Windows_x86_64.exe
20f471458a1e92c1365cdb31af1c7cfc4b34e5bb1f6ebbbadba86be6d7bf4819  snyk-iac-test_0.35.2_Darwin_x86_64
45a3267eae64a71d74985aef751e265ddc6f363d6eceeef9bd01c2a9c2d34f96  snyk-iac-test_0.35.2_Linux_arm64
4ceb48a4151f2b488cd5fbbd15a32f15acbf4b8d3c09ea32a88f4d5b5070bb97  snyk-iac-test_0.35.2_Linux_x86_64
817be2b3e3babd526f261b5b7714c0a97288d8fe98fca6b702eb26c17a382c39  snyk-iac-test_0.35.2_Darwin_arm64
a5383697a029eaf96d1b7775ac7e37839b43b2b8161b8ba063ae9315c7bef3ac  snyk-iac-test_0.35.2_Windows_arm64.exe
`;

export const policyEngineVersion = getPolicyEngineVersion();

export function formatPolicyEngineFileName(releaseVersion: string): string {
  let platform = 'Linux';
  switch (os.platform()) {
    case 'darwin':
      platform = 'Darwin';
      break;
    case 'win32':
      platform = 'Windows';
      break;
  }

  const arch = os.arch() === 'arm64' ? 'arm64' : 'x86_64';

  const execExt = os.platform() === 'win32' ? '.exe' : '';

  return `snyk-iac-test_${releaseVersion}_${platform}_${arch}${execExt}`;
}

export function getChecksum(policyEngineFileName: string): string {
  const lines = policyEngineChecksums.split(/\r?\n/);
  const checksumsMap = new Map<string, string>();

  for (const line of lines) {
    const [checksum, file] = line.split(/\s+/);

    if (file && checksum) {
      checksumsMap.set(file, checksum.trim());
    }
  }

  const policyEngineChecksum = checksumsMap.get(policyEngineFileName);

  if (!policyEngineChecksum) {
    // This is an internal error and technically it should never be thrown
    throw new Error(`Could not find checksum for ${policyEngineFileName}`);
  }

  return policyEngineChecksum;
}

function getPolicyEngineVersion(): string {
  const lines = policyEngineChecksums.split(/\r?\n/);

  if (lines.length == 0) {
    throw new Error('empty checksum');
  }

  const line = lines.find((line) => line.length > 0);

  if (line === undefined) {
    throw new Error('empty checksum lines');
  }

  const parts = line.split(/\s+/);

  if (parts.length < 2) {
    throw new Error('invalid checksum line');
  }

  const components = parts[1].split('_');

  if (components.length < 2) {
    throw new Error('invalid checksum file name');
  }

  return components[1];
}
