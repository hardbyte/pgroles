import { Fragment, useEffect, useId, useMemo, useRef, useState } from 'react'
import Highlight, { defaultProps } from 'prism-react-renderer'

import {
  getPgrolesSemanticRanges,
  splitSemanticToken,
} from '@/components/PgrolesPolicyHighlight'

function CopyButton({ copied, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={copied ? 'Copied' : 'Copy code'}
      className="rounded-md p-1.5 text-stone-400 transition hover:bg-stone-800 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-300"
    >
      {copied ? <CopiedIcon /> : <CopyIcon />}
    </button>
  )
}

function HighlightedCode({ code, language, schema }) {
  const isPgrolesManifest = schema === 'pgroles-manifest'
  const legendId = useId()
  const semantic = useMemo(
    () =>
      isPgrolesManifest
        ? getPgrolesSemanticRanges(code)
        : { ranges: [], errors: [] },
    [code, isPgrolesManifest]
  )
  const lineStarts = useMemo(() => {
    let offset = 0
    return code.split('\n').map((line) => {
      const start = offset
      offset += line.length + 1
      return start
    })
  }, [code])

  return (
    <>
      {isPgrolesManifest && (
        <div
          id={legendId}
          className="flex flex-wrap gap-x-4 gap-y-1 border-b border-stone-800 bg-[#0c0e12] px-4 py-2 font-mono text-[9px] uppercase tracking-[0.1em] text-stone-400"
        >
          <span>
            <span className="font-semibold text-amber-300">Section</span>
          </span>
          <span>
            <span className="text-sky-300">Field</span>
          </span>
          <span>
            <span className="text-teal-200">Role / profile / setting</span>
          </span>
          <span>
            <span className="text-cyan-200">Object</span>
          </span>
          <span>
            <span className="font-semibold text-pink-300">
              Privilege / type
            </span>
          </span>
          <span>
            <span className="text-rose-300 underline decoration-wavy">
              Unknown
            </span>
          </span>
        </div>
      )}
      <Highlight
        {...defaultProps}
        code={code}
        language={isPgrolesManifest ? 'yaml' : language}
        theme={undefined}
      >
        {({ className, style, tokens, getTokenProps }) => (
          <pre
            className={`${className} m-0 rounded-none px-4 py-5`}
            style={style}
            aria-describedby={isPgrolesManifest ? legendId : undefined}
          >
            <code>
              {tokens.map((line, lineIndex) => {
                let tokenStart = lineStarts[lineIndex] || 0

                return (
                  <Fragment key={lineIndex}>
                    {line
                      .filter((token) => !token.empty)
                      .flatMap((token) => {
                        const pieces = splitSemanticToken(
                          token,
                          tokenStart,
                          semantic.ranges
                        )
                        tokenStart += token.content.length
                        return pieces
                      })
                      .map(({ token, start }) => {
                        const props = getTokenProps({ token })
                        return (
                          <span
                            key={`${start}-${token.content}`}
                            {...props}
                            className={`${props.className || ''} ${
                              token.semanticClassName || ''
                            }`.trim()}
                            title={token.semanticTitle}
                          />
                        )
                      })}
                    {'\n'}
                  </Fragment>
                )
              })}
            </code>
          </pre>
        )}
      </Highlight>
      {semantic.errors.length > 0 && (
        <p
          className="m-0 border-t border-rose-900/70 bg-rose-950/40 px-4 py-3 font-mono text-xs text-rose-200"
          role="status"
        >
          YAML syntax: {semantic.errors[0]}
        </p>
      )}
    </>
  )
}

export function Fence({ children, language, schema }) {
  const [copied, setCopied] = useState(false)
  const resetCopy = useRef()
  const code = String(children).trimEnd()
  const isPgrolesPolicy = schema === 'pgroles-manifest'

  function onCopyCode() {
    navigator.clipboard.writeText(children).then(() => setCopied(true))
  }

  useEffect(() => {
    if (copied) resetCopy.current = setTimeout(() => setCopied(false), 2500)
    return () => clearTimeout(resetCopy.current)
  }, [copied])

  if (isPgrolesPolicy) {
    return (
      <div className="not-prose my-6 overflow-hidden rounded-2xl border border-stone-700 bg-[#0c0e12] shadow-sm">
        <div className="flex items-center justify-between gap-3 border-b border-stone-700 bg-stone-900 px-4 py-2.5">
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate font-mono text-xs font-semibold text-stone-200">
              pgroles.yaml
            </span>
            <span className="rounded-full border border-teal-800 bg-teal-950/60 px-2 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-[0.12em] text-teal-300">
              policy schema
            </span>
          </div>
          <CopyButton copied={copied} onClick={onCopyCode} />
        </div>
        <HighlightedCode code={code} language={language} schema={schema} />
      </div>
    )
  }

  return (
    <div className="relative">
      <span className="absolute right-3 top-3 z-10">
        <CopyButton copied={copied} onClick={onCopyCode} />
      </span>
      <HighlightedCode code={code} language={language} />
    </div>
  )
}

function CopyIcon() {
  return (
    <svg
      aria-hidden="true"
      stroke="currentColor"
      width="20"
      height="20"
      fill="transparent"
      viewBox="0 0 24 24"
      xmlns="http://www.w3.org/2000/svg"
      shapeRendering="geometricPrecision"
      strokeLinejoin="round"
      strokeLinecap="round"
    >
      <path d="M8 17.929H6c-1.105 0-2-.912-2-2.036V5.036C4 3.91 4.895 3 6 3h8c1.105 0 2 .911 2 2.036v1.866m-6 .17h8c1.105 0 2 .91 2 2.035v10.857C20 21.09 19.105 22 18 22h-8c-1.105 0-2-.911-2-2.036V9.107c0-1.124.895-2.036 2-2.036z" />
    </svg>
  )
}

function CopiedIcon() {
  return (
    <svg
      aria-hidden="true"
      width="20"
      height="20"
      fill="currentColor"
      viewBox="0 0 1024 1024"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M688 312v-48c0-4.4-3.6-8-8-8H296c-4.4 0-8 3.6-8 8v48c0 4.4 3.6 8 8 8h384c4.4 0 8-3.6 8-8zm-392 88c-4.4 0-8 3.6-8 8v48c0 4.4 3.6 8 8 8h184c4.4 0 8-3.6 8-8v-48c0-4.4-3.6-8-8-8H296zm376 116c-119.3 0-216 96.7-216 216s96.7 216 216 216 216-96.7 216-216-96.7-216-216-216zm107.5 323.5C750.8 868.2 712.6 884 672 884s-78.8-15.8-107.5-44.5C535.8 810.8 520 772.6 520 732s15.8-78.8 44.5-107.5C593.2 595.8 631.4 580 672 580s78.8 15.8 107.5 44.5C808.2 653.2 824 691.4 824 732s-15.8 78.8-44.5 107.5zM761 656h-44.3c-2.6 0-5 1.2-6.5 3.3l-63.5 87.8-23.1-31.9a7.92 7.92 0 0 0-6.5-3.3H573c-6.5 0-10.3 7.4-6.5 12.7l73.8 102.1c3.2 4.4 9.7 4.4 12.9 0l114.2-158c3.9-5.3.1-12.7-6.4-12.7zM440 852H208V148h560v344c0 4.4 3.6 8 8 8h56c4.4 0 8-3.6 8-8V108c0-17.7-14.3-32-32-32H168c-17.7 0-32 14.3-32 32v784c0 17.7 14.3 32 32 32h272c4.4 0 8-3.6 8-8v-56c0-4.4-3.6-8-8-8z" />
    </svg>
  )
}
