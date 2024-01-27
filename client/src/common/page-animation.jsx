import { AnimatePresence, animate, motion } from "framer-motion";

const AnimationWrapper = ({
  children,
  keyValue,
  className,
  // initial = { opacity: 0, top: -100, position: "relative" },
  // animate = { opacity: 1, top: 0 },
  initial = { opacity: 0 },
  animate = { opacity: 1 },
  transition = { duration: 1 },
}) => {
  return (
    <AnimatePresence>
      <motion.div
        key={keyValue}
        initial={initial}
        animate={animate}
        transition={transition}
        className={className}
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
};

export default AnimationWrapper;
