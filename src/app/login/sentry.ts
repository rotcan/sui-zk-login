// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import * as Sentry from '@sentry/browser';

export function initSentry() {
	Sentry.addTracingExtensions();
	Sentry.init(
        {
        defaultIntegrations: false,
        tracesSampleRate: 1,
        integrations: [
          new Sentry.Integrations.FunctionToString(),
          new Sentry.Integrations.LinkedErrors(),
        ],
        }
	);
}
