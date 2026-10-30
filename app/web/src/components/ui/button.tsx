import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { Slot } from 'radix-ui'

import { cn } from '@/lib/utils'

const buttonVariants = cva(
  "inline-flex shrink-0 cursor-pointer items-center justify-center gap-1.5 rounded-md border border-transparent font-medium whitespace-nowrap transition-colors select-none disabled:pointer-events-none disabled:opacity-50 aria-disabled:pointer-events-none aria-disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-zinc-700',
        outline:
          'border-border-strong bg-surface text-foreground hover:bg-subtle aria-expanded:bg-subtle',
        secondary: 'bg-subtle text-foreground hover:bg-zinc-200 aria-expanded:bg-zinc-200',
        ghost: 'text-foreground hover:bg-subtle aria-expanded:bg-subtle',
        destructive:
          'border-transparent bg-destructive text-white hover:bg-[color-mix(in_oklab,var(--color-destructive),black_15%)]',
        link: 'h-auto border-0 px-0 text-foreground underline decoration-border-strong underline-offset-4 hover:decoration-foreground',
      },
      size: {
        default: 'h-8 px-3 text-sm',
        sm: 'h-7 gap-1 px-2.5 text-dense [&_svg:not([class*=size-])]:size-3.5',
        xs: 'h-6 gap-1 rounded-sm px-2 text-xs [&_svg:not([class*=size-])]:size-3',
        lg: 'h-9 px-4 text-sm',
        icon: 'size-8',
        'icon-sm': 'size-7 [&_svg:not([class*=size-])]:size-3.5',
        'icon-xs': 'size-6 rounded-sm [&_svg:not([class*=size-])]:size-3',
      },
    },
    compoundVariants: [{ variant: 'link', className: 'h-auto px-0' }],
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  },
)

function Button({
  className,
  variant = 'default',
  size = 'default',
  asChild = false,
  ...props
}: React.ComponentProps<'button'> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot.Root : 'button'

  return (
    <Comp
      data-slot="button"
      data-variant={variant}
      data-size={size}
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  )
}

export { Button, buttonVariants }
