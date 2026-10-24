// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

/** An error that is safe to show to API clients. */
class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

const errors = {
  invalidPackage: (msg) => new ApiError(400, 'invalid_package', msg),
  notFound: (msg) => new ApiError(404, 'not_found', msg),
  versionNotFound: (msg) => new ApiError(404, 'version_not_found', msg),
  noArtifact: (msg) => new ApiError(422, 'no_artifact', msg),
  upstream: (msg) => new ApiError(502, 'upstream_error', msg),
  timeout: (msg) => new ApiError(504, 'timeout', msg),
  busy: () => new ApiError(503, 'busy', 'The scanner is at capacity. Try again in a few seconds.'),
};

module.exports = { ApiError, errors };
