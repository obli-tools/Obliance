import { clsx } from 'clsx';

interface StyledCheckboxProps {
 checked: boolean;
 onChange: (checked: boolean) => void;
 indeterminate?: boolean;
 disabled?: boolean;
 className?: string;
}

export function StyledCheckbox({ checked, onChange, indeterminate, disabled, className }: StyledCheckboxProps) {
 return (
 <button
 type="button"
 role="checkbox"
 aria-checked={indeterminate ? 'mixed' : checked}
 disabled={disabled}
 onClick={() => !disabled && onChange(!checked)}
 className={clsx(
 'w-4 h-4 rounded border-2 flex items-center justify-center transition-all duration-150 shrink-0',
 // Touch: invisible 40×40 hit area around
 // the 16px box without moving the layout, and a visible unchecked
 // border (there is no hover to reveal it on a touch screen).
 "relative coarse:after:absolute coarse:after:-inset-3 coarse:after:content-['']",
 checked || indeterminate
 ? 'bg-accent border-accent text-white'
 // Unchecked: a filled, visible box at rest (mouse and touch alike),
 // matching the "selection mode" treatment DeviceRow.tsx already gives
 // its own row checkboxes. It used to be bg-transparent border-transparent
 // with only a hover reveal — invisible to a user who never happens to
 // hover the exact 16px box (the "select all" header checkbox especially,
 // since nothing else on that row draws attention to hovering it).
 : 'bg-bg-primary/80 border-text-muted/40 hover:border-accent/60',
 disabled && 'opacity-40 cursor-not-allowed',
 !disabled && 'cursor-pointer',
 className,
 )}
 >
 {checked && (
 <svg className="w-2.5 h-2.5" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round" strokeLinejoin="round">
 <path d="M2 6l3 3 5-5" />
 </svg>
 )}
 {indeterminate && !checked && (
 <svg className="w-2.5 h-2.5" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth={2.5} strokeLinecap="round">
 <path d="M2 6h8" />
 </svg>
 )}
 </button>
 );
}
