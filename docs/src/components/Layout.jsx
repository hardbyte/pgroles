import {useCallback, useEffect, useState} from 'react'
import Link from 'next/link'
import {useRouter} from 'next/router'
import clsx from 'clsx'

import {Hero} from '@/components/Hero'
import {Logo, Logomark} from '@/components/Logo'
import {MobileNavigation} from '@/components/MobileNavigation'
import {Navigation} from '@/components/Navigation'
import {Prose} from '@/components/Prose'
import {Search} from '@/components/Search'
import {ThemeSelector} from '@/components/ThemeSelector'

const navigation = [
    {
        title: 'Introduction',
        links: [
            {title: 'Getting started', href: '/'},
            {title: 'Quick start', href: '/docs/quick-start'},
            {title: 'Related tools', href: '/docs/alternatives'},
        ],
    },
    {
        title: 'User Guide',
        links: [
            {title: 'Installation', href: '/docs/installation'},
            {title: 'Manifest format', href: '/docs/manifest-format'},
            {title: 'Profiles & schemas', href: '/docs/profiles'},
            {title: 'Grants & privileges', href: '/docs/grants'},
            {title: 'Default privileges', href: '/docs/default-privileges'},
            {title: 'Memberships', href: '/docs/memberships'},
        ],
    },
    {
        title: 'Deployment',
        links: [
            {title: 'CI/CD integration', href: '/docs/ci-cd'},
            {title: 'Google Cloud SQL', href: '/docs/google-cloud-sql'},
            {title: 'AWS RDS & Aurora', href: '/docs/aws-rds'},
            {title: 'Staged adoption', href: '/docs/adoption'},
            {title: 'Kubernetes operator', href: '/docs/operator'},
            {title: 'Operator architecture', href: '/docs/operator-architecture'},
        ],
    },
    {
        title: 'Reference',
        links: [
            {title: 'CLI commands', href: '/docs/cli'},
            {title: 'Architecture', href: '/docs/architecture'},
        ],
    },
]

function GitHubIcon(props) {
    return (
        <svg aria-hidden="true" viewBox="0 0 16 16" {...props}>
            <path
                d="M8 0C3.58 0 0 3.58 0 8C0 11.54 2.29 14.53 5.47 15.59C5.87 15.66 6.02 15.42 6.02 15.21C6.02 15.02 6.01 14.39 6.01 13.72C4 14.09 3.48 13.23 3.32 12.78C3.23 12.55 2.84 11.84 2.5 11.65C2.22 11.5 1.82 11.13 2.49 11.12C3.12 11.11 3.57 11.7 3.72 11.94C4.44 13.15 5.59 12.81 6.05 12.6C6.12 12.08 6.33 11.73 6.56 11.53C4.78 11.33 2.92 10.64 2.92 7.58C2.92 6.71 3.23 5.99 3.74 5.43C3.66 5.23 3.38 4.41 3.82 3.31C3.82 3.31 4.49 3.1 6.02 4.13C6.66 3.95 7.34 3.86 8.02 3.86C8.7 3.86 9.38 3.95 10.02 4.13C11.55 3.09 12.22 3.31 12.22 3.31C12.66 4.41 12.38 5.23 12.3 5.43C12.81 5.99 13.12 6.7 13.12 7.58C13.12 10.65 11.25 11.33 9.47 11.53C9.76 11.78 10.01 12.26 10.01 13.01C10.01 14.08 10 14.94 10 15.21C10 15.42 10.15 15.67 10.55 15.59C13.71 14.53 16 11.53 16 8C16 3.58 12.42 0 8 0Z"/>
        </svg>
    )
}

function Header({navigation}) {
    let [isScrolled, setIsScrolled] = useState(false)

    useEffect(() => {
        function onScroll() {
            setIsScrolled(window.scrollY > 0)
        }

        onScroll()
        window.addEventListener('scroll', onScroll, {passive: true})
        return () => {
            window.removeEventListener('scroll', onScroll, {passive: true})
        }
    }, [])

    return (
        <header
            className={clsx(
                'sticky top-0 z-50 flex flex-wrap items-center justify-between border-b px-4 py-4 transition duration-300 sm:px-6 lg:px-8',
                isScrolled
                    ? 'border-stone-300 bg-stone-50/92 shadow-[0_10px_30px_-24px_rgba(28,25,23,0.55)] backdrop-blur dark:border-stone-800 dark:bg-stone-950/88 dark:shadow-none'
                    : 'border-transparent bg-stone-100/90 dark:bg-stone-950'
            )}
        >
            <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-[linear-gradient(90deg,transparent,rgba(245,158,11,0.6),rgba(20,184,166,0.45),transparent)]" />
            <div className="mr-6 flex lg:hidden">
                <MobileNavigation navigation={navigation}/>
            </div>
            <div className="relative flex flex-grow basis-0 items-center">
                <Link href="/" aria-label="Home page">
                    <Logomark className="h-9 w-9 lg:hidden"/>
                    <Logo className="hidden lg:flex"/>
                </Link>
            </div>
            <div className="-my-5 mr-6 sm:mr-8 md:mr-0">
                <Search/>
            </div>
            <div className="relative flex basis-0 justify-end gap-6 sm:gap-8 md:flex-grow">
                <ThemeSelector className="relative z-10"/>
                <Link href="https://github.com/hardbyte/pgroles" className="group" aria-label="GitHub">
                    <GitHubIcon
                        className="h-6 w-6 fill-stone-500 transition group-hover:fill-amber-600 dark:fill-stone-400 dark:group-hover:fill-amber-300"/>
                </Link>
            </div>
        </header>
    )
}

function useTableOfContents(tableOfContents) {
    let [currentSection, setCurrentSection] = useState(tableOfContents[0]?.id)

    let getHeadings = useCallback((tableOfContents) => {
        return tableOfContents
            .flatMap((node) => [node.id, ...node.children.map((child) => child.id)])
            .map((id) => {
                let el = document.getElementById(id)
                if (!el) return

                let style = window.getComputedStyle(el)
                let scrollMt = parseFloat(style.scrollMarginTop)

                let top = window.scrollY + el.getBoundingClientRect().top - scrollMt
                return {id, top}
            })
    }, [])

    useEffect(() => {
        if (tableOfContents.length === 0) return
        let headings = getHeadings(tableOfContents)

        function onScroll() {
            let top = window.scrollY
            let current = headings[0].id
            for (let heading of headings) {
                if (top >= heading.top) {
                    current = heading.id
                } else {
                    break
                }
            }
            setCurrentSection(current)
        }

        window.addEventListener('scroll', onScroll, {passive: true})
        onScroll()
        return () => {
            window.removeEventListener('scroll', onScroll, {passive: true})
        }
    }, [getHeadings, tableOfContents])

    return currentSection
}

export function Layout({children, title, tableOfContents}) {
    let router = useRouter()
    let isHomePage = router.pathname === '/'
    let allLinks = navigation.flatMap((section) => section.links)
    let linkIndex = allLinks.findIndex((link) => link.href === router.pathname)
    let previousPage = allLinks[linkIndex - 1]
    let nextPage = allLinks[linkIndex + 1]
    let section = navigation.find((section) =>
        section.links.find((link) => link.href === router.pathname)
    )
    let currentSection = useTableOfContents(tableOfContents)

    function isActive(section) {
        if (section.id === currentSection) {
            return true
        }
        if (!section.children) {
            return false
        }
        return section.children.findIndex(isActive) > -1
    }

    return (
        <>
            <Header navigation={navigation}/>

            {isHomePage && <Hero/>}

            <div className="relative bg-stone-100 text-stone-900 dark:bg-stone-950 dark:text-stone-100">
            <div className="relative mx-auto flex max-w-8xl justify-center sm:px-2 lg:px-8 xl:px-12">
                <div className="hidden lg:relative lg:block lg:flex-none">
                    <div
                        className="sticky top-[4.5rem] -ml-0.5 h-[calc(100vh-4.5rem)] overflow-y-auto overflow-x-hidden py-16 pl-0.5">
                        <Navigation
                            navigation={navigation}
                            className="w-64 rounded-r-[2rem] border-r border-stone-300/80 bg-stone-50/70 pr-8 shadow-[8px_0_24px_-24px_rgba(28,25,23,0.3)] xl:w-72 xl:pr-16 dark:border-stone-800 dark:bg-stone-950/40 dark:shadow-none"
                        />
                    </div>
                </div>
                <div className="min-w-0 max-w-2xl flex-auto px-4 py-16 lg:max-w-none lg:pr-0 lg:pl-8 xl:px-16">
                    <article>
                        {(title || section) && (
                            <header className="mb-10 space-y-2">
                                {section && (
                                    <p className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-amber-700 dark:text-amber-300">
                                        {section.title}
                                    </p>
                                )}
                                {title && (
                                    <h1 className="font-display text-4xl tracking-[-0.03em] text-stone-950 dark:text-stone-100">
                                        {title}
                                    </h1>
                                )}
                            </header>
                        )}
                        <Prose>{children}</Prose>
                    </article>
                    <dl className="mt-12 flex border-t border-stone-300 pt-6 dark:border-stone-800">
                        {previousPage && (
                            <div>
                                <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
                                    Previous
                                </dt>
                                <dd className="mt-1">
                                    <Link
                                        href={previousPage.href}
                                        className="text-base font-semibold text-stone-700 hover:text-amber-700 dark:text-stone-300 dark:hover:text-amber-300"
                                    >
                                        <span aria-hidden="true">&larr;</span> {previousPage.title}
                                    </Link>
                                </dd>
                            </div>
                        )}
                        {nextPage && (
                            <div className="ml-auto text-right">
                                <dt className="font-display text-[11px] font-semibold uppercase tracking-[0.2em] text-stone-500 dark:text-stone-400">
                                    Next
                                </dt>
                                <dd className="mt-1">
                                    <Link
                                        href={nextPage.href}
                                        className="text-base font-semibold text-stone-700 hover:text-amber-700 dark:text-stone-300 dark:hover:text-amber-300"
                                    >
                                        {nextPage.title} <span aria-hidden="true">&rarr;</span>
                                    </Link>
                                </dd>
                            </div>
                        )}
                    </dl>
                </div>
                <div
                    className="hidden xl:sticky xl:top-[4.5rem] xl:-mr-6 xl:block xl:h-[calc(100vh-4.5rem)] xl:flex-none xl:overflow-y-auto xl:py-16 xl:pr-6">
                    <nav aria-labelledby="on-this-page-title" className="w-56 rounded-[1.75rem] border border-stone-300/80 bg-white/80 p-5 shadow-[0_18px_40px_-34px_rgba(28,25,23,0.45)] dark:border-stone-700 dark:bg-stone-900/80 dark:shadow-none">
                        {tableOfContents.length > 0 && (
                            <>
                                <h2
                                    id="on-this-page-title"
                                    className="font-display text-[11px] font-semibold uppercase tracking-[0.22em] text-stone-500 dark:text-stone-400"
                                >
                                    On this page
                                </h2>
                                <ol role="list" className="mt-4 space-y-3 text-sm">
                                    {tableOfContents.map((section) => (
                                        <li key={section.id}>
                                            <h3>
                                                <Link
                                                    href={`#${section.id}`}
                                                    className={clsx(
                                                        isActive(section)
                                                            ? 'text-amber-700 dark:text-amber-300'
                                                            : 'font-normal text-stone-600 hover:text-stone-900 dark:text-stone-400 dark:hover:text-stone-200'
                                                    )}
                                                >
                                                    {section.title}
                                                </Link>
                                            </h3>
                                            {section.children.length > 0 && (
                                                <ol
                                                    role="list"
                                                    className="mt-2 space-y-3 pl-5 text-stone-500 dark:text-stone-500"
                                                >
                                                    {section.children.map((subSection) => (
                                                        <li key={subSection.id}>
                                                            <Link
                                                                href={`#${subSection.id}`}
                                                                className={
                                                                    isActive(subSection)
                                                                        ? 'text-amber-700 dark:text-amber-300'
                                                                        : 'hover:text-stone-900 dark:hover:text-stone-200'
                                                                }
                                                            >
                                                                {subSection.title}
                                                            </Link>
                                                        </li>
                                                    ))}
                                                </ol>
                                            )}
                                        </li>
                                    ))}
                                </ol>
                            </>
                        )}
                    </nav>
                </div>
            </div>
            </div>
        </>
    )
}
