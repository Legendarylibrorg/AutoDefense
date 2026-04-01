import React, { Component, type ReactNode } from "react";

type Props = { children: ReactNode };
type State = { error: Error | null };

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center p-8">
          <div className="max-w-lg rounded-xl border border-danger/30 bg-panel p-6 text-center">
            <div className="text-lg font-semibold text-danger">Dashboard error</div>
            <pre className="mt-4 whitespace-pre-wrap break-words rounded-lg bg-black/30 p-3 text-left text-xs text-muted">
              {this.state.error.message}
            </pre>
            <button
              className="mt-4 rounded-lg border border-accent/40 bg-accent/20 px-4 py-2 text-sm text-text hover:bg-accent/30"
              onClick={() => this.setState({ error: null })}
            >
              Retry
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
