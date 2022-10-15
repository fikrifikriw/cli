import * as modulesParser from './npm-modules-parser';
import * as lockParser from './npm-lock-parser';
import * as types from '../types';
import * as analytics from '../../analytics';
import { MissingTargetFileError } from '../../errors/missing-targetfile-error';
import { MultiProjectResult } from '@snyk/cli-interface/legacy/plugin';
import { DepGraph } from '@snyk/dep-graph';
import { PkgTree } from 'snyk-nodejs-lockfile-parser';

export async function inspect(
  root: string,
  targetFile: string,
  options: types.Options = {},
): Promise<MultiProjectResult> {
  if (!targetFile) {
    throw MissingTargetFileError(root);
  }
  const isLockFileBased =
    targetFile.endsWith('package-lock.json') ||
    targetFile.endsWith('yarn.lock');

  const getLockFileDeps = isLockFileBased && !options.traverseNodeModules;
  const depRes: PkgTree | DepGraph = getLockFileDeps
    ? await lockParser.parse(root, targetFile, options)
    : await modulesParser.parse(root, targetFile, options);

  const isDepGraph = isResDepGraph(depRes);

  let scannedProjects: any[] = [];
  if (isDepGraph) {
    if ((depRes as DepGraph)?.pkgManager.version) {
      analytics.add(
        'lockfileVersion',
        (depRes as DepGraph)?.pkgManager.version,
      );
    }
    scannedProjects = [{ depGraph: depRes }];
  } else {
    if ((depRes as PkgTree)?.meta?.lockfileVersion) {
      analytics.add(
        'lockfileVersion',
        (depRes as PkgTree)?.meta?.lockfileVersion,
      );
    }
    scannedProjects = [{ depTree: depRes }];
  }

  return {
    plugin: {
      name: 'snyk-nodejs-lockfile-parser',
      runtime: process.version,
    },
    scannedProjects,
  };
}

function isResDepGraph(depRes: PkgTree | DepGraph): boolean {
  return 'rootPkg' in depRes;
}
